import os
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import jwt
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

# =========================
# ENV
# =========================
SECRET = os.getenv("LICENSE_SECRET", "RINBELL_SUPER_SECRET_2026")
ADMIN_KEY = os.getenv("ADMIN_KEY", "RINBELL_ADMIN_2026")
DB_URL = os.getenv("DB_URL")
ONLINE_WINDOW_SECONDS = int(os.getenv("ONLINE_WINDOW_SECONDS", "120"))

if not DB_URL:
    raise RuntimeError("DB_URL not set")


def ensure_sslmode_require(url: str) -> str:
    if url.startswith(("postgresql://", "postgres://")):
        parts = urlparse(url)
        query = dict(parse_qsl(parts.query))
        if "sslmode" not in query:
            query["sslmode"] = "require"
            parts = parts._replace(query=urlencode(query))
            return urlunparse(parts)
    return url


DB_URL = ensure_sslmode_require(DB_URL)

# =========================
# APP / DB
# =========================
app = FastAPI(title="License Server")

if DB_URL.startswith("sqlite"):
    engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DB_URL, pool_pre_ping=True, pool_recycle=300)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True, nullable=False)
    hwid = Column(String, nullable=True)
    active = Column(Boolean, default=True)
    note = Column(String, default="")
    last_seen_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def db():
    return SessionLocal()


def ensure_schema():
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    if "licenses" not in inspector.get_table_names():
        return

    cols = {col["name"] for col in inspector.get_columns("licenses")}
    if "last_seen_at" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE licenses ADD COLUMN last_seen_at TIMESTAMP NULL"))


@app.on_event("startup")
def on_startup():
    ensure_schema()


# =========================
# MODELS
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
# UTILS
# =========================
def create_token(key: str):
    payload = {
        "key": key,
        "iat": int(time.time()),
        "exp": int(time.time()) + (15 * 24 * 60 * 60),  # 15 วัน
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def decode_token(token: str):
    return jwt.decode(token, SECRET, algorithms=["HS256"])


def require_admin(x_admin_key: str | None):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="forbidden")


def normalize_key(value: str) -> str:
    return (value or "").strip()


def is_online(last_seen_at: datetime | None) -> bool:
    if not last_seen_at:
        return False
    return (datetime.utcnow() - last_seen_at) <= timedelta(seconds=ONLINE_WINDOW_SECONDS)


# =========================
# HEALTH CHECK
# =========================
@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}


# =========================
# VERIFY LOGIN
# =========================
@app.post("/verify")
def verify(data: VerifyRequest):
    key = normalize_key(data.key)
    hwid = normalize_key(data.hwid)

    if not key or not hwid:
        raise HTTPException(status_code=422, detail="missing_key_or_hwid")

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()

        if not lic:
            raise HTTPException(status_code=403, detail="invalid_key")

        if not lic.active:
            raise HTTPException(status_code=403, detail="banned")

        if not lic.hwid:
            lic.hwid = hwid

        if lic.hwid != hwid:
            raise HTTPException(status_code=403, detail="hwid_mismatch")

        lic.last_seen_at = datetime.utcnow()
        session.commit()

        return {
            "status": "ok",
            "token": create_token(key),
            "hwid_bound": True,
        }
    finally:
        session.close()


# =========================
# HEARTBEAT
# =========================
@app.get("/heartbeat")
def heartbeat(authorization: str | None = Header(default=None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="no_token")

    token = authorization.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="no_token")

    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_token")

    key = normalize_key(payload.get("key", ""))
    if not key:
        raise HTTPException(status_code=401, detail="invalid_token")

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()
        if not lic or not lic.active:
            raise HTTPException(status_code=403, detail="banned")

        lic.last_seen_at = datetime.utcnow()
        session.commit()

        return {"status": "ok"}
    finally:
        session.close()


# =========================
# ADMIN
# =========================
@app.post("/admin/add")
def admin_add(data: KeyRequest, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    key = normalize_key(data.key)
    if not key:
        raise HTTPException(status_code=422, detail="missing_key")

    session = db()
    try:
        existing = session.query(License).filter_by(license_key=key).first()
        if existing:
            raise HTTPException(status_code=409, detail="key_exists")

        lic = License(
            license_key=key,
            note=(data.note or "").strip(),
            active=True,
            hwid=None,
            last_seen_at=None,
        )
        session.add(lic)
        session.commit()
        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/reset")
def admin_reset(data: ResetRequest, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    key = normalize_key(data.key)
    if not key:
        raise HTTPException(status_code=422, detail="missing_key")

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()
        if not lic:
            raise HTTPException(status_code=404, detail="not_found")

        lic.hwid = None
        lic.last_seen_at = None
        session.commit()
        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/ban")
def admin_ban(data: BanRequest, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)

    key = normalize_key(data.key)
    if not key:
        raise HTTPException(status_code=422, detail="missing_key")

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()
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

    key = normalize_key(data.key)
    if not key:
        raise HTTPException(status_code=422, detail="missing_key")

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()
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
                "online": is_online(r.last_seen_at),
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                "note": r.note,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            }
            for r in rows
        ]
    finally:
        session.close()
