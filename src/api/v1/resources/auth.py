from fastapi import APIRouter, Depends, HTTPException, status

from src.api.v1.schemas import (AuthUser, SignupUser, Token, UserModel,
                                UserProfile)
from src.core.token import create_tokens, validate_token
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
    payload = validate_token(tokens.get("refresh_token"))
    refresh_jti = payload.get("jti")
    user_uuid = payload.get("user_uuid")
    auth_service.active_refresh_tokens_cache.add(key=user_uuid, value=refresh_jti)
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
    current_user = user_service.get_current_user(refresh_token, is_refresh_token=True)
    tokens = create_tokens(UserProfile(**current_user))
    payload = validate_token(tokens.get("refresh_token"))
    user_uuid = payload.get("user_uuid")
    refresh_jti = payload.get("jti")
    user_service.active_refresh_tokens_cache.add(key=user_uuid, value=refresh_jti)
    return Token(**tokens)


@router.post(
    path="/logout",
    summary="Выйти с текущего устройства",
    tags=["auth"],
)
def logout(access_token: str = Depends(oauth2_scheme),
           auth_service: AuthService = Depends(get_auth_service)) -> dict:
    """Вернет сообщение об успешном выходе из системы с одного устройства."""
    payload = validate_token(access_token)
    access_jti = payload.get("jti")
    blocked_token = auth_service.blocked_access_tokens_cache.get(key=access_jti)
    if blocked_token:
        # Если токен заблокирован, отдаём 401 статус
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="the access token is expired")
    refresh_jti = payload.get("refresh_jti")
    user_uuid = payload.get("user_uuid")
    auth_service.blocked_access_tokens_cache.set(key=access_jti, value="block")
    auth_service.active_refresh_tokens_cache.remove(key=user_uuid, value=refresh_jti)
    return {"msg": "You have been logged out."}


@router.post(
    path="/logout_all",
    summary="Выйти со всех устройств",
    tags=["auth"],
)
def logout_all(access_token: str = Depends(oauth2_scheme),
               auth_service: AuthService = Depends(get_auth_service)) -> dict:
    """Вернет сообщение об успешном выходе из системы со всех устройств."""
    payload = validate_token(access_token)
    access_jti = payload.get("jti")
    blocked_token = auth_service.blocked_access_tokens_cache.get(key=access_jti)
    if blocked_token:
        # Если токен заблокирован, отдаём 401 статус
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="the access token is expired")
    user_uuid = payload.get("user_uuid")
    auth_service.blocked_access_tokens_cache.set(key=access_jti, value="block")
    auth_service.active_refresh_tokens_cache.clear(key=user_uuid)
    return {"msg": "You have been logged out from all devices."}
