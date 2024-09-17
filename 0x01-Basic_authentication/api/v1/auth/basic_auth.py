#!/usr/bin/env python3
"""
    This module will contain the auth class
"""
from flask import request
import base64
from models.user import User
from typing import List, TypeVar
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ This is the BasicAuthentication class
    """

    def __init__(self) -> None:
        super().__init__()

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ This Method  returns the Base64 part of the Authorization header

        Args:
            authorization_header (str): authorization header

        Returns:
            str:
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        split = authorization_header.split()
        if len(split) < 2:
            return None
        stat = split[0]
        auth = split[1]

        if stat != 'Basic':
            return None
        return auth

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """ This Method returns the decoded value of a Base64 string
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_byte = base64.b64decode(base64_authorization_header)
            decoded_str = decoded_byte.decode('utf-8')
            return decoded_str
        except BaseException:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """ This method returns the user email and password.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        username, password = decoded_base64_authorization_header.split(':', 1)
        return username, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his email and password.
        """
        if user_email is None:
            return None
        if user_pwd is None:
            return None
        user = User()
        users = user.search({'email': user_email})
        if users:
            for a_user in users:
                if a_user.is_valid_password(user_pwd):
                    return a_user
            return None
        else:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ overloads Auth and retrieves the User instance for a request
        """
        if request is None:
            return None

        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None

        base64_part = self.extract_base64_authorization_header(auth_header)
        if base64_part is None:
            return None

        decoded_part = self.decode_base64_authorization_header(base64_part)
        if decoded_part is None:
            return None

        email, pwd = self.extract_user_credentials(decoded_part)
        if email is None or pwd is None:
            return None

        user = self.user_object_from_credentials(email, pwd)
        return user
