from fastapi import APIRouter, Depends

from src.api.v1.schemas import (AuthUser, SignupUser, Token, UserModel,
                                         UserProfile)
from src.core.token import create_tokens
from src.services import (AuthService, UserService, get_auth_service,
                                   get_user_service, oauth2_scheme)

router = APIRouter()


@router.post(
    path="/signup",
    status_code=201,
    summary="Зарегистрировать пользователя",
    tags=["auth"],
)
def user_create(user: SignupUser,
                auth_service: AuthService = Depends(get_auth_service)) -> dict:
    """Вернет информацию о созданном пользователе."""
    user: dict = auth_service.register_new_user(user=user)
    response = {"msg": "User created."}
    response.update({"user": UserModel(**user)})
    return response


@router.post(
    path="/login",
    response_model=Token,
    summary="Авторизовать пользователя",
    tags=["auth"],
)
def login(user: AuthUser,
          auth_service: AuthService = Depends(get_auth_service)) -> Token:
    """Вернет access и refresh JWT."""
    user_data = auth_service.authenticate_user(user)
    tokens = create_tokens(UserProfile(**user_data))
    return Token(**tokens)


@router.post(
    path="/refresh",
    response_model=Token,
    summary="Обновить токены",
    tags=["auth"],
)
def get_new_tokens(refresh_token: str = Depends(oauth2_scheme),
                   user_service: UserService = Depends(get_user_service)) -> Token:
    """Вернет обновленные access и refresh JWT."""
    current_user = user_service.get_current_user(refresh_token)
    tokens = create_tokens(UserProfile(**current_user))
    return Token(**tokens)
