import uuid
from calendar import timegm
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt

from src.api.v1.schemas import UserProfile
from src.core import config

__all__ = ("create_tokens", "validate_token")


def convert_to_unix_timestamp(time: datetime) -> int:
    return timegm(time.utctimetuple())


def create_access_token(utc_now: datetime, refresh_jti: str, user: UserProfile) -> str:
    user_data = user.dict()
    utc_exp = convert_to_unix_timestamp(
        utc_now + timedelta(minutes=config.JWT_EXPIRE_IN_MINUTES)
    )
    utc_now = convert_to_unix_timestamp(utc_now)
    payload = {
        "iat": utc_now,
        "jti": str(uuid.uuid4()),
        "type": "access",
        "user_uuid": str(user_data.pop("uuid")),
        "nbf": utc_now,
        "exp": utc_exp,
        "refresh_jti": refresh_jti,
    }
    user_data["created_at"] = str(user.created_at)
    payload.update(user_data)
    token = jwt.encode(payload, key=config.JWT_SECRET_KEY,
                       algorithm=config.JWT_ALGORITHM)
    return token


def create_refresh_token(utc_now: datetime, jti: str, user_uuid: str) -> str:
    utc_exp = convert_to_unix_timestamp(
        utc_now + timedelta(days=config.JWT_REFRESH_EXPIRE_IN_DAYS)
    )
    utc_now = convert_to_unix_timestamp(utc_now)
    payload = {
        "iat": utc_now,
        "jti": jti,
        "type": "refresh",
        "user_uuid": user_uuid,
        "nbf": utc_now,
        "exp": utc_exp,
    }
    token = jwt.encode(payload, key=config.JWT_SECRET_KEY,
                       algorithm=config.JWT_ALGORITHM)
    return token


def create_tokens(user: UserProfile) -> dict:
    user_uuid = str(user.uuid)
    refresh_jti = str(uuid.uuid4())
    utc_now = datetime.utcnow()
    refresh_token = create_refresh_token(utc_now=utc_now, jti=refresh_jti,
                                         user_uuid=user_uuid)
    access_token = create_access_token(utc_now=utc_now, refresh_jti=refresh_jti,
                                       user=user)
    return {"access_token": access_token, "refresh_token": refresh_token}


def validate_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, key=config.JWT_SECRET_KEY,
                             algorithms=config.JWT_ALGORITHM)
    except JWTError:
        return
    return payload
