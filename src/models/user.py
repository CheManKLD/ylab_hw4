import uuid as uuid_pkg
from datetime import datetime

from pydantic import EmailStr
from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel

__all__ = ("User",)


class User(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("username"),
                      UniqueConstraint("email"),)
    uuid: uuid_pkg.UUID = Field(default_factory=uuid_pkg.uuid4, primary_key=True)
    username: str = Field(max_length=150, nullable=False)
    email: EmailStr = Field(nullable=False)
    password: str = Field(max_length=128, nullable=False)
    created_at: datetime = Field(default=datetime.utcnow(), nullable=False)
    is_superuser: bool = Field(default=False, nullable=False)
    is_totp_enabled: bool = Field(default=False, nullable=False)
    is_active: bool = Field(default=True, nullable=False)
