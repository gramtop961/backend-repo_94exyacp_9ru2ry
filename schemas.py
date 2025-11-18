"""
Database Schemas for Hospital Management System (Auth module)

Each Pydantic model corresponds to a MongoDB collection (class name lowercased).

- Patient -> "patient"
- otpcode -> "otpcode"
- session -> "session"

These are used for validation and also help tooling introspect your data model.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

class Patient(BaseModel):
    full_name: str = Field(..., description="Full name of the patient")
    email: EmailStr = Field(..., description="Unique email for login and notifications")
    phone: str = Field(..., description="Contact number used for OTP login (E.164 preferred)")
    password_hash: str = Field(..., description="Hashed password (server-generated)")
    salt: str = Field(..., description="Password salt (server-generated)")
    role: str = Field("patient", description="User role, defaults to patient")
    is_active: bool = Field(True, description="Whether the account is active")

class Otpcode(BaseModel):
    channel: str = Field(..., description="email or phone")
    target: str = Field(..., description="email address or phone number where code was sent")
    code: str = Field(..., description="6-digit OTP code")
    purpose: str = Field(..., description="login or reset")
    expires_at: datetime = Field(..., description="Expiration timestamp (UTC)")
    consumed: bool = Field(False, description="Whether this code has been used")

class Session(BaseModel):
    user_id: str = Field(..., description="Associated patient _id as string")
    token: str = Field(..., description="Opaque session token stored client-side")
    expires_at: datetime = Field(..., description="Session expiry")
    active: bool = Field(True, description="Whether session is active")
