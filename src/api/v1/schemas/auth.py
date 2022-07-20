from pydantic import BaseModel, EmailStr, Field

__all__ = (
    "Token",
    "SignupUser",
    "AuthUser",
)


class AuthBase(BaseModel):
    username: str


class SignupUser(AuthBase):
    email: EmailStr
    password: str = Field(min_length=5, max_length=20)


class AuthUser(AuthBase):
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
