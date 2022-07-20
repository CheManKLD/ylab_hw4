import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

__all__ = (
    "UserModel",
    "UserProfile",
    "UserUpdate",
)


class UserBase(BaseModel):
    username: str


class UserModel(UserBase):
    created_at: datetime
    is_superuser: bool
    uuid: uuid.UUID
    is_totp_enabled: bool
    is_active: bool
    email: str


class UserProfile(BaseModel):
    uuid: uuid.UUID
    username: str
    email: str
    is_superuser: bool
    created_at: datetime


class UserUpdate(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    password: Optional[str] = Field(min_length=5, max_length=20)
