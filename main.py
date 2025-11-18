import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Utility helpers
# ---------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def generate_numeric_code(n: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(n))


# ---------------------------
# Request/Response Models
# ---------------------------

class SignupPayload(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    password: str


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordPayload(BaseModel):
    email: EmailStr


class ResetPasswordPayload(BaseModel):
    token: str
    new_password: str


class OTPRequestPayload(BaseModel):
    channel: str  # "email" or "phone"
    target: str   # email address or phone number
    purpose: str  # "login" or "reset"


class OTPVerifyPayload(BaseModel):
    target: str
    code: str
    purpose: str


# ---------------------------
# Password hashing (simple PBKDF2)
# ---------------------------
import hashlib
import os as _os


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if salt is None:
        salt = _os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return dk.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    dk, _salt = hash_password(password, salt)
    return secrets.compare_digest(dk, password_hash)


# ---------------------------
# Public endpoints
# ---------------------------

@app.get("/")
def read_root():
    return {"message": "Hospital Management API - Auth ready"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


# ---------------------------
# Auth flows
# ---------------------------

@app.post("/auth/signup")
def signup(payload: SignupPayload):
    # Ensure unique email
    existing = db["patient"].find_one({"email": payload.email}) if db else None
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    phash, salt = hash_password(payload.password)
    patient_doc = {
        "full_name": payload.full_name,
        "email": payload.email,
        "phone": payload.phone,
        "password_hash": phash,
        "salt": salt,
        "role": "patient",
        "is_active": True,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    result = db["patient"].insert_one(patient_doc)
    return {"message": "Signup successful", "user_id": str(result.inserted_id)}


@app.post("/auth/login")
def login(payload: LoginPayload):
    user = db["patient"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password_hash", ""), user.get("salt", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")

    token = generate_token(32)
    session = {
        "user_id": str(user["_id"]),
        "token": token,
        "expires_at": now_utc() + timedelta(days=7),
        "active": True,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    db["session"].insert_one(session)
    return {"message": "Login successful", "token": token, "profile": {
        "id": str(user["_id"]),
        "full_name": user.get("full_name"),
        "email": user.get("email"),
        "phone": user.get("phone"),
        "role": user.get("role", "patient")
    }}


@app.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordPayload):
    user = db["patient"].find_one({"email": payload.email})
    if not user:
        # don't reveal existence
        return {"message": "If that account exists, a reset link will be sent"}

    token = generate_token(24)
    expires = now_utc() + timedelta(hours=1)
    db["reset_tokens"].insert_one({
        "user_id": str(user["_id"]),
        "token": token,
        "expires_at": expires,
        "created_at": now_utc(),
    })
    # In real system, send email/SMS. Here we return the token for demo/testing
    return {"message": "Reset token generated", "token": token, "expires_at": expires.isoformat()}


@app.post("/auth/reset-password")
def reset_password(payload: ResetPasswordPayload):
    rec = db["reset_tokens"].find_one({"token": payload.token})
    if not rec or rec.get("expires_at") < now_utc():
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user_id = rec.get("user_id")
    phash, salt = hash_password(payload.new_password)
    db["patient"].update_one({"_id": ObjectId(user_id)}, {"$set": {"password_hash": phash, "salt": salt, "updated_at": now_utc()}})
    db["reset_tokens"].delete_one({"_id": rec["_id"]})
    return {"message": "Password updated"}


@app.post("/auth/otp/request")
def request_otp(payload: OTPRequestPayload):
    if payload.channel not in {"email", "phone"}:
        raise HTTPException(status_code=400, detail="Invalid channel")
    code = generate_numeric_code(6)
    expires = now_utc() + timedelta(minutes=10)

    db["otpcode"].insert_one({
        "channel": payload.channel,
        "target": payload.target,
        "code": code,
        "purpose": payload.purpose,
        "expires_at": expires,
        "consumed": False,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    })

    # In real system, send code via email/SMS. For demo, return the code.
    return {"message": "OTP generated", "code": code, "expires_at": expires.isoformat()}


@app.post("/auth/otp/verify")
def verify_otp(payload: OTPVerifyPayload):
    rec = db["otpcode"].find_one({
        "target": payload.target,
        "code": payload.code,
        "purpose": payload.purpose,
        "consumed": False,
    })
    if not rec or rec.get("expires_at") < now_utc():
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    db["otpcode"].update_one({"_id": rec["_id"]}, {"$set": {"consumed": True, "updated_at": now_utc()}})

    # If purpose is login and the user exists, create session
    user = db["patient"].find_one({"email": payload.target}) or db["patient"].find_one({"phone": payload.target})
    if not user:
        # Auto-create minimal account for OTP login via phone/email
        user_doc = {
            "full_name": payload.target,
            "email": payload.target if "@" in payload.target else f"{payload.target}@otp.local",
            "phone": payload.target if "@" not in payload.target else "",
            "password_hash": "",
            "salt": "",
            "role": "patient",
            "is_active": True,
            "created_at": now_utc(),
            "updated_at": now_utc(),
        }
        ins = db["patient"].insert_one(user_doc)
        user = db["patient"].find_one({"_id": ins.inserted_id})

    token = generate_token(32)
    session = {
        "user_id": str(user["_id"]),
        "token": token,
        "expires_at": now_utc() + timedelta(days=7),
        "active": True,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    db["session"].insert_one(session)

    return {"message": "OTP verified", "token": token, "profile": {
        "id": str(user["_id"]),
        "full_name": user.get("full_name"),
        "email": user.get("email"),
        "phone": user.get("phone"),
        "role": user.get("role", "patient")
    }}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
