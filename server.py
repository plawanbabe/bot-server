import os
import time
from datetime import datetime

import jwt
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# 🔐 SECRET / ADMIN (เปลี่ยนแล้ว)
SECRET = os.getenv("LICENSE_SECRET", "RINBELL_SUPER_SECRET_2026")
ADMIN_KEY = os.getenv("ADMIN_KEY", "RINBELL_ADMIN_2026")

# 💾 DB (Render-safe path)
DB_URL = os.getenv("DB_URL", "sqlite:///./licenses.db")

app = FastAPI(title="License Server")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True, nullable=False)
    hwid = Column(String, nullable=True)
    active = Column(Boolean, default=True)
    note = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# =========================
# 📦 REQUEST MODELS
# =========================
class VerifyRequest(BaseModel):
    key: str
    hwid: str


class KeyRequest(BaseModel):
    key: str
    note: str | None = ""


class ResetRequest(BaseModel):
    key: str


class BanRequest(BaseModel):
    key: str


# =========================
# 🔧 UTILS
# =========================
def db():
    return SessionLocal()


def create_token(key: str):
    payload = {
        "key": key,
        "iat": int(time.time()),
        "exp": int(time.time()) + (15 * 24 * 60 * 60)  # 15 วัน
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def decode_token(token: str):
    return jwt.decode(token, SECRET, algorithms=["HS256"])


def require_admin(x_admin_key: str | None):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="forbidden")


# =========================
# 🌐 HEALTH CHECK (สำคัญสำหรับ Render)
# =========================
@app.get("/")
def root():
    return {"status": "ok"}


# =========================
# 🔐 VERIFY LOGIN
# =========================
@app.post("/verify")
def verify(data: VerifyRequest):
    session = db()
    try:
        lic = session.query(License).filter_by(license_key=data.key).first()

        if not lic:
            raise HTTPException(status_code=403, detail="invalid_key")

        if not lic.active:
            raise HTTPException(status_code=403, detail="banned")

        # bind ครั้งแรก
        if not lic.hwid:
            lic.hwid = data.hwid
            session.commit()

        if lic.hwid != data.hwid:
            raise HTTPException(status_code=403, detail="hwid_mismatch")

        return {
            "status": "ok",
            "token": create_token(data.key),
            "hwid_bound": True
        }
    finally:
        session.close()


# =========================
# ❤️ HEARTBEAT (เช็คทุก 10 นาที)
# =========================
@app.get("/heartbeat")
def heartbeat(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="no_token")

    token = authorization.replace("Bearer ", "").strip()

    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_token")

    key = payload.get("key")
    if not key:
        raise HTTPException(status_code=401, detail="invalid_token")

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()
        if not lic or not lic.active:
            raise HTTPException(status_code=403, detail="banned")

        return {"status": "ok"}
    finally:
        session.close()


# =========================
# 🛠 ADMIN
# =========================
@app.post("/admin/add")
def admin_add(data: KeyRequest, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    session = db()
    try:
        existing = session.query(License).filter_by(license_key=data.key).first()
        if existing:
            raise HTTPException(status_code=409, detail="key_exists")

        lic = License(
            license_key=data.key,
            note=data.note or "",
            active=True,
            hwid=None
        )
        session.add(lic)
        session.commit()
        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/reset")
def admin_reset(data: ResetRequest, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=data.key).first()
        if not lic:
            raise HTTPException(status_code=404, detail="not_found")

        lic.hwid = None
        session.commit()
        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/ban")
def admin_ban(data: BanRequest, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=data.key).first()
        if not lic:
            raise HTTPException(status_code=404, detail="not_found")

        lic.active = False
        session.commit()
        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/unban")
def admin_unban(data: BanRequest, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=data.key).first()
        if not lic:
            raise HTTPException(status_code=404, detail="not_found")

        lic.active = True
        session.commit()
        return {"status": "ok"}
    finally:
        session.close()


@app.get("/admin/list")
def admin_list(x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    session = db()
    try:
        rows = session.query(License).order_by(License.id.desc()).all()
        return [
            {
                "key": r.license_key,
                "hwid": r.hwid,
                "active": r.active,
                "note": r.note,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rows
        ]
    finally:
        session.close()