from fastapi import APIRouter, Depends

from src.api.v1.schemas import UserModel, UserProfile, UserUpdate
from src.core.token import create_tokens
from src.services import UserService, get_user_service
from src.services.auth import oauth2_scheme

router = APIRouter()


@router.get(
    path="/me",
    summary="Получить информацию об авторизованном пользователе",
    tags=["users"]
)
def get_current_user(token: str = Depends(oauth2_scheme),
                     user_service: UserService = Depends(get_user_service)) -> dict:
    """Вернет информацию об авторизованном пользователе."""
    current_user = user_service.get_current_user(token)
    return {"user": UserProfile(**current_user)}


@router.patch(
    path="/me",
    summary="Обновить информацию авторизованного пользователя",
    tags=["users"]
)
def update_current_user(new_data: UserUpdate,
                        token: str = Depends(oauth2_scheme),
                        user_service: UserService = Depends(get_user_service)) -> dict:
    """Вернет обновленную информацию авторизованного пользователя."""
    updated_user = user_service.update_user(token=token, new_data=new_data)
    new_tokens = create_tokens(UserProfile(**updated_user))
    response = {"msg": "Update is successful. Please use new access token."}
    response.update({"user": UserModel(**updated_user).dict()})
    response.update(new_tokens)
    return response
