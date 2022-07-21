from typing import NoReturn, Optional, Union

from src.core import config
from src.db import AbstractCache, ListAbstractCache

__all__ = ("CacheRedis",)


class CacheRedis(AbstractCache):
    def get(self, key: str) -> Optional[dict]:
        return self.cache.get(name=key)

    def set(
        self,
        key: str,
        value: Union[bytes, str],
        expire: int = config.CACHE_EXPIRE_IN_SECONDS,
    ):
        self.cache.set(name=key, value=value, ex=expire)

    def close(self) -> NoReturn:
        self.cache.close()


class AccessTokenCacheRedis(CacheRedis):
    def set(
        self,
        key: str,
        value: Union[bytes, str],
        expire: int = config.CACHE_JWT_EXPIRE_IN_SECONDS,
    ) -> None:
        self.cache.set(name=key, value=value, ex=expire)


class RefreshTokenCacheRedis(ListAbstractCache):
    def add(self, key: str, value: str) -> None:
        self.cache.sadd(key, value)

    def remove(self, key: str, value: Union[bytes, str]) -> None:
        self.cache.srem(key, value)

    def clear(self, key: str) -> None:
        self.cache.delete(key)

    def find(self, key: str, value: Union[bytes, str]) -> bool:
        return self.cache.sismember(name=key, value=value)

    def close(self) -> NoReturn:
        self.cache.close()
