from passlib.hash import bcrypt

__all__ = ("get_hash_password", "verify_password")


def get_hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.verify(password, password_hash)
