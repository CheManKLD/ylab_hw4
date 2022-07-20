from functools import lru_cache

from fastapi import Depends, HTTPException, status
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from src.api.v1.schemas import UserUpdate
from src.core.security import get_hash_password
from src.core.token import validate_token
from src.db import AbstractCache, get_cache, get_session
from src.models import User
from src.services import ServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):
    def get_current_user(self, token: str) -> dict:
        """Вернет информацию об аутентифицированном пользователе."""
        exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                  detail="could not validate credentials")
        payload = validate_token(token)
        if not payload:
            # Если токен не прошел валидацию, отдаём 401 статус
            raise exception
        user_uuid = payload.get("user_uuid")
        user = self.session.get(User, user_uuid)
        if not user:
            # Если пользователь не найден, отдаём 401 статус
            raise exception
        return user.dict()

    def update_user(self, token: str, new_data: UserUpdate) -> dict:
        """Вернет обновленную информацию об аутентифицированном пользователе."""
        payload = validate_token(token)
        if not payload:
            # Если токен не прошел валидацию, отдаём 401 статус
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="could not validate credentials")
        user_uuid = payload.get("user_uuid")
        user = self.session.get(User, user_uuid)
        for key, value in new_data.dict(exclude_unset=True).items():
            if key == "password" and value:
                value = get_hash_password(value)
            if value:
                setattr(user, key, value)
        try:
            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
        except IntegrityError as error:
            # Если username или email уже существует, отдаём 400 статус
            assert isinstance(error.orig, UniqueViolation)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="username or email is already exists")
        return user.dict()


@lru_cache()
def get_user_service(cache: AbstractCache = Depends(get_cache),
                     session: Session = Depends(get_session)) -> UserService:
    return UserService(cache=cache, session=session)
