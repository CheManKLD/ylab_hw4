from sqlmodel import Session

from src.db import AbstractCache, ListAbstractCache


class ServiceMixin:
    def __init__(self, cache: AbstractCache, session: Session):
        self.cache: AbstractCache = cache
        self.session: Session = session


class AuthServiceMixin:
    def __init__(
        self,
        blocked_access_tokens_cache: AbstractCache,
        active_refresh_tokens_cache: ListAbstractCache,
        session: Session
    ):
        self.blocked_access_tokens_cache: AbstractCache = blocked_access_tokens_cache
        self.active_refresh_tokens_cache: ListAbstractCache = active_refresh_tokens_cache
        self.session: Session = session
