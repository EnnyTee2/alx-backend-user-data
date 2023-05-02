#!/usr/bin/env python3

"""
Definition of _hash_password function
"""
import bcrypt
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound
from typing import (
    TypeVar,
    Union
)

from db import DB
from user import User

U = TypeVar(User)


def _hash_password(password: str) -> bytes:
    """
    Hashes a password string and returns it in bytes form
    Args:
        password (str): password in string format
    """
    passwd = password.encode('utf-8')
    return bcrypt.hashpw(passwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generates a uuid and return its string representation
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        registers a new user with the email and password passed
        then returns the new User object.
        Args:
            email (str): email in string format
            password (str): password in string format
        Return:
                if user does not exist previously, register and
                return new User object else raise ValuError
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hash = _hash_password(password)
            user = self._db.add_user(email, hash)
            return user
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate a user's login credentials and return True if correct
        or False if incorrect
        Args:
            email (str): user's email address
            password (str): user's password
        Return:
            True if credentials are correct, False if incorrect
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        user_pwd = user.hashed_password
        passwd = password.encode("utf-8")
        return bcrypt.checkpw(passwd, user_pwd)

    def create_session(self, email: str) -> Union[None, str]:
        """
        Create a session id for an existing user and store in the
        session_id database record
        Args:
            email (str): user's email address
        Return:
               The created session_id, if user
               is found else return None
        
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id
