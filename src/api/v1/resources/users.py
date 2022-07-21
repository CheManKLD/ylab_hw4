from fastapi import APIRouter, Depends

from src.api.v1.schemas import UserModel, UserProfile, UserUpdate
from src.core.token import create_tokens, validate_token
from src.services import UserService, get_user_service
from src.services.auth import oauth2_scheme

router = APIRouter()


@router.get(
    path="/me",
    summary="Получить информацию об авторизованном пользователе",
    tags=["users"]
)
def get_current_user(access_token: str = Depends(oauth2_scheme),
                     user_service: UserService = Depends(get_user_service)) -> dict:
    """Вернет информацию об авторизованном пользователе."""
    current_user = user_service.get_current_user(access_token)
    return {"user": UserProfile(**current_user)}


@router.patch(
    path="/me",
    summary="Обновить информацию авторизованного пользователя",
    tags=["users"]
)
def update_current_user(new_data: UserUpdate,
                        access_token: str = Depends(oauth2_scheme),
                        user_service: UserService = Depends(get_user_service)) -> dict:
    """Вернет обновленную информацию авторизованного пользователя."""
    updated_user = user_service.update_user(access_token=access_token, new_data=new_data)
    new_tokens = create_tokens(UserProfile(**updated_user))
    payload = validate_token(new_tokens.get("refresh_token"))
    user_uuid = payload.get("user_uuid")
    refresh_jti = payload.get("jti")
    user_service.active_refresh_tokens_cache.add(key=user_uuid, value=refresh_jti)
    response = {"msg": "Update is successful. Please use new access token."}
    response.update({"user": UserModel(**updated_user).dict()})
    response.update(new_tokens)
    return response
