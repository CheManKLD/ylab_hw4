from functools import lru_cache

from fastapi import Depends, HTTPException, status
from psycopg2.errors import UniqueViolation
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from src.api.v1.schemas import UserUpdate
from src.core.security import get_hash_password
from src.core.token import validate_token
from src.db import (AbstractCache, ListAbstractCache, get_access_tokens_cache,
                    get_refresh_tokens_cache, get_session)
from src.models import User
from src.services import AuthServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(AuthServiceMixin):
    def get_current_user(self, token: str,
                         is_refresh_token: bool = False) -> dict:
        """Вернет информацию об аутентифицированном пользователе."""
        exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        payload = validate_token(token)
        user_uuid = payload.get("user_uuid")
        if is_refresh_token:
            refresh_jti = payload.get("jti")
            is_active_token = self.active_refresh_tokens_cache.find(key=user_uuid,
                                                                    value=refresh_jti)
            if not is_active_token:
                # Если токен не активен, отдаём 401 статус
                exception.detail = "the refresh token is expired"
                raise exception
        else:
            access_jti = payload.get("jti")
            blocked_token = self.blocked_access_tokens_cache.get(key=access_jti)
            if blocked_token:
                # Если токен заблокирован, отдаём 401 статус
                exception.detail = "the access token is expired"
                raise exception
        user = self.session.get(User, user_uuid)
        if not user:
            # Если пользователь не найден, отдаём 401 статус
            raise exception
        return user.dict()

    def update_user(self, access_token: str, new_data: UserUpdate) -> dict:
        """Вернет обновленную информацию об аутентифицированном пользователе."""
        payload = validate_token(access_token)
        access_jti = payload.get("jti")
        blocked_token = self.blocked_access_tokens_cache.get(key=access_jti)
        if blocked_token:
            # Если токен заблокирован, отдаём 401 статус
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="the access token is expired")
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
        access_jti = payload.get("jti")
        self.blocked_access_tokens_cache.set(key=access_jti, value="block")
        return user.dict()


@lru_cache()
def get_user_service(
    blocked_access_tokens_cache: AbstractCache = Depends(get_access_tokens_cache),
    active_refresh_tokens_cache: ListAbstractCache = Depends(get_refresh_tokens_cache),
    session: Session = Depends(get_session)
) -> UserService:
    return UserService(blocked_access_tokens_cache=blocked_access_tokens_cache,
                       active_refresh_tokens_cache=active_refresh_tokens_cache,
                       session=session)
