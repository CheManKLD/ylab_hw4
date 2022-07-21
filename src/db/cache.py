from abc import ABC, abstractmethod
from typing import Optional, Union

from redis import Redis

from src.core import config

__all__ = (
    "AbstractCache",
    "ListAbstractCache",
    "get_cache",
    "get_access_tokens_cache",
    "get_refresh_tokens_cache",
)


class AbstractCache(ABC):
    def __init__(self, cache_instance: Redis):
        self.cache = cache_instance

    @abstractmethod
    def get(self, key: str):
        pass

    @abstractmethod
    def set(
        self,
        key: str,
        value: Union[bytes, str],
        expire: int = config.CACHE_EXPIRE_IN_SECONDS,
    ):
        pass

    @abstractmethod
    def close(self):
        pass


class ListAbstractCache(ABC):
    def __init__(self, cache_instance: Redis):
        self.cache = cache_instance

    @abstractmethod
    def add(self, key: str, value: Union[bytes, str]):
        pass

    @abstractmethod
    def remove(self, key: str, value: Union[bytes, str]):
        pass

    @abstractmethod
    def clear(self, key: str):
        pass

    @abstractmethod
    def find(self, key: str, value: Union[bytes, str]):
        pass

    @abstractmethod
    def close(self):
        pass


cache: Optional[AbstractCache] = None
blocked_access_tokens_cache: Optional[AbstractCache] = None
active_refresh_tokens_cache: Optional[ListAbstractCache] = None


# Функция понадобится при внедрении зависимостей
def get_cache() -> AbstractCache:
    return cache


def get_access_tokens_cache() -> AbstractCache:
    return blocked_access_tokens_cache


def get_refresh_tokens_cache() -> ListAbstractCache:
    return active_refresh_tokens_cache
