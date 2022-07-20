from pydantic import BaseModel

__all__ = (
    "Token",
    "SignupUser",
    "AuthUser",
)


class AuthBase(BaseModel):
    username: str


class SignupUser(AuthBase):
    email: str
    password: str


class AuthUser(AuthBase):
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
