from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from psycopg2.errors import UniqueViolation
from pydantic import EmailError, validate_email
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from src.api.v1.schemas import AuthUser, SignupUser
from src.core.security import get_hash_password, verify_password
from src.db import AbstractCache, get_cache, get_session
from src.models import User
from src.services import ServiceMixin

__all__ = ("AuthService", "get_auth_service", "oauth2_scheme")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")


class AuthService(ServiceMixin):
    def register_new_user(self, user: SignupUser) -> dict:
        """Вернет информацию о новом созданном пользователе."""
        exception = HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        user.email = user.email.lower()
        try:
            validate_email(user.email)
        except EmailError:
            # Если email не прошел валидацию, отдаём 400 статус
            exception.detail = "invalid email format"
            raise exception
        hash_password = get_hash_password(user.password)
        new_user = User(username=user.username, password=hash_password,
                        email=user.email)
        try:
            self.session.add(new_user)
            self.session.commit()
            self.session.refresh(new_user)
        except IntegrityError as error:
            # Если username или email уже существует, отдаём 400 статус
            assert isinstance(error.orig, UniqueViolation)
            exception.detail = "username or email is already exists"
            raise exception
        return new_user.dict()

    def authenticate_user(self, user_data: AuthUser) -> dict:
        """Вернет информацию об аутентифицированном пользователе."""
        user = self.session.query(User).filter(
            User.username == user_data.username
        ).first()
        if not user or not verify_password(user_data.password, user.password):
            # Если пользователь не найден или пароль неправильный, отдаём 401 статус
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="incorrect username or password")
        return user.dict()


@lru_cache()
def get_auth_service(cache: AbstractCache = Depends(get_cache),
                     session: Session = Depends(get_session)) -> AuthService:
    return AuthService(cache=cache, session=session)
