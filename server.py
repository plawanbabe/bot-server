import os
import time
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import jwt
import requests
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

# 🔥 URL ของตัวเอง (สำคัญมาก)
SELF_URL = os.getenv("SELF_URL", "https://bot-server-7v1f.onrender.com")

ONLINE_WINDOW = 120  # วินาที

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
# APP
# =========================
app = FastAPI(title="License Server")

engine = create_engine(DB_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


# =========================
# MODEL
# =========================
class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True)
    license_key = Column(String, unique=True, index=True, nullable=False)
    hwid = Column(String, nullable=True)
    active = Column(Boolean, default=True)
    note = Column(String, default="")
    last_seen_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def db():
    return SessionLocal()


# =========================
# AUTO MIGRATION
# =========================
def ensure_schema():
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("licenses")}

    if "last_seen_at" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE licenses ADD COLUMN last_seen_at TIMESTAMP"))


@app.on_event("startup")
def startup():
    ensure_schema()

    # 🔥 กัน sleep (ยิงตัวเองทุก 5 นาที)
    def keep_alive():
        while True:
            try:
                requests.get(SELF_URL, timeout=10)
            except:
                pass
            time.sleep(300)

    threading.Thread(target=keep_alive, daemon=True).start()


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
def normalize(x):
    return (x or "").strip()


def create_token(key):
    return jwt.encode(
        {
            "key": key,
            "exp": int(time.time()) + 15 * 24 * 3600,
        },
        SECRET,
        algorithm="HS256",
    )


def decode_token(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])


def require_admin(x_admin_key):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "forbidden")


def is_online(last_seen):
    if not last_seen:
        return False
    return (datetime.utcnow() - last_seen) <= timedelta(seconds=ONLINE_WINDOW)


# =========================
# ROUTES
# =========================
@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/verify")
def verify(data: VerifyRequest):
    key = normalize(data.key)
    hwid = normalize(data.hwid)

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()

        if not lic:
            raise HTTPException(403, "invalid_key")

        if not lic.active:
            raise HTTPException(403, "banned")

        if not lic.hwid:
            lic.hwid = hwid

        if lic.hwid != hwid:
            raise HTTPException(403, "hwid_mismatch")

        lic.last_seen_at = datetime.utcnow()
        session.commit()

        return {
            "status": "ok",
            "token": create_token(key),
        }
    finally:
        session.close()


@app.get("/heartbeat")
def heartbeat(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(401, "no_token")

    token = authorization.replace("Bearer ", "")
    payload = decode_token(token)
    key = payload.get("key")

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=key).first()

        if not lic or not lic.active:
            raise HTTPException(403, "banned")

        lic.last_seen_at = datetime.utcnow()
        session.commit()

        return {"status": "ok"}
    finally:
        session.close()


# =========================
# ADMIN
# =========================
@app.get("/admin/list")
def admin_list(x_admin_key: str = Header(None)):
    require_admin(x_admin_key)

    session = db()
    try:
        rows = session.query(License).all()

        return [
            {
                "key": r.license_key,
                "hwid": r.hwid,
                "active": r.active,
                "online": is_online(r.last_seen_at),
                "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                "note": r.note,
            }
            for r in rows
        ]
    finally:
        session.close()


@app.post("/admin/add")
def add(data: KeyRequest, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)

    session = db()
    try:
        if session.query(License).filter_by(license_key=data.key).first():
            raise HTTPException(409, "exists")

        session.add(License(license_key=data.key))
        session.commit()
        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/reset")
def reset(data: ResetRequest, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=data.key).first()
        if not lic:
            raise HTTPException(404, "not_found")

        lic.hwid = None
        lic.last_seen_at = None
        session.commit()

        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/ban")
def ban(data: BanRequest, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=data.key).first()
        if not lic:
            raise HTTPException(404, "not_found")

        lic.active = False
        session.commit()

        return {"status": "ok"}
    finally:
        session.close()


@app.post("/admin/unban")
def unban(data: BanRequest, x_admin_key: str = Header(None)):
    require_admin(x_admin_key)

    session = db()
    try:
        lic = session.query(License).filter_by(license_key=data.key).first()
        if not lic:
            raise HTTPException(404, "not_found")

        lic.active = True
        session.commit()

        return {"status": "ok"}
    finally:
        session.close()
