#!/usr/bin/env python3
"""
Definition of class BasicAuth
"""
import base64
from .auth import Auth
from typing import TypeVar

from models.user import User


class BasicAuth(Auth):
    """
    This class provides basic authentication
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header for
        implementing Basic Authorization
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        auth_header = authorization_header.split(" ")[-1]
        return auth_header

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """
        Decodes the Base64 encoded part of the Authorization header
        string
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            encoded_auth = base64_authorization_header.encode('utf-8')
            encoded_auth = base64.b64decode(encoded_auth)
            return decoded_auth.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
        Returns user email and password from Base64 decoded value
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        email = decoded_base64_authorization_header.split(":")[0]
        pwd = decoded_base64_authorization_header[len(email) + 1:]
        return (email, pwd)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Return a User instance based on email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({"email": user_email})
            if not users or users == []:
                return None
            for userr in users:
                if userr.is_valid_password(user_pwd):
                    return userr
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns a User instance based on a received request
        """
        auth_string = self.authorization_header(request)
        if auth_string is not None:
            header = self.extract_base64_authorization_header(auth_string)
            if header is not None:
                decoded = self.decode_base64_authorization_header(header)
                if decoded is not None:
                    email, pwd = self.extract_user_credentials(decoded)
                    if email is not None:
                        return self.user_object_from_credentials(email, pwd)
        return
