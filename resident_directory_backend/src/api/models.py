from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

# For database integration
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, ForeignKey, Enum as SAEnum, Text
)
from sqlalchemy.orm import declarative_base

import enum

Base = declarative_base()


# Role enumeration
class UserRoleEnum(str, enum.Enum):
    admin = "admin"
    resident = "resident"
    moderator = "moderator"


# SQLAlchemy Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(SAEnum(UserRoleEnum), nullable=False)
    name = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Residents can update their own info, admins create others


class Resident(Base):
    __tablename__ = "residents"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    unit = Column(String, nullable=False, index=True)
    phone = Column(String, nullable=True)
    email = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime, default=datetime.utcnow)

    # Optionally: history relationship for audit log


class ModerationRequest(Base):
    __tablename__ = "moderation_requests"
    id = Column(Integer, primary_key=True)
    resident_id = Column(Integer, ForeignKey("residents.id"))
    requestor_id = Column(Integer, ForeignKey("users.id"))  # User who requested
    field = Column(String, nullable=False)  # Field being changed
    old_value = Column(Text)
    new_value = Column(Text)
    status = Column(
        SAEnum("pending", "approved", "rejected", name="moderationstatus"), default="pending"
    )
    requested_at = Column(DateTime, default=datetime.utcnow)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False)
    target_type = Column(String, nullable=False)  # 'resident', 'user', etc.
    target_id = Column(Integer)
    changes = Column(Text)  # JSON string or similar
    timestamp = Column(DateTime, default=datetime.utcnow)


# Pydantic Schemas

# PUBLIC_INTERFACE
class ResidentBase(BaseModel):
    name: str = Field(..., description="Full name of the resident")
    unit: str = Field(..., description="Apartment or unit number")
    phone: Optional[str] = Field(None, description="Contact phone number")
    email: Optional[EmailStr] = Field(None, description="Email address")


# PUBLIC_INTERFACE
class ResidentCreate(ResidentBase):
    pass


# PUBLIC_INTERFACE
class ResidentUpdate(BaseModel):
    name: Optional[str]
    unit: Optional[str]
    phone: Optional[str]
    email: Optional[EmailStr]


# PUBLIC_INTERFACE
class ResidentResponse(ResidentBase):
    id: int
    is_active: bool
    updated_by: Optional[int]
    updated_at: datetime

    class Config:
        orm_mode = True


# PUBLIC_INTERFACE
class UserBase(BaseModel):
    email: EmailStr
    role: UserRoleEnum
    name: Optional[str]


# PUBLIC_INTERFACE
class UserCreate(UserBase):
    password: str


# PUBLIC_INTERFACE
class UserLogin(BaseModel):
    email: EmailStr
    password: str


# PUBLIC_INTERFACE
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserBase


# PUBLIC_INTERFACE
class ModerationRequestBase(BaseModel):
    resident_id: int
    field: str
    old_value: Optional[str]
    new_value: str


# PUBLIC_INTERFACE
class ModerationRequestCreate(ModerationRequestBase):
    pass


# PUBLIC_INTERFACE
class ModerationRequestResponse(ModerationRequestBase):
    id: int
    requestor_id: int
    status: str
    requested_at: datetime
    reviewed_by: Optional[int]
    reviewed_at: Optional[datetime]

    class Config:
        orm_mode = True


# PUBLIC_INTERFACE
class AuditLogResponse(BaseModel):
    id: int
    user_id: int
    action: str
    target_type: str
    target_id: int
    changes: Optional[str]
    timestamp: datetime

    class Config:
        orm_mode = True
