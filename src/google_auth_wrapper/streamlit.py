# Copyright 2025 Ubie, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This module provides a decorator to check if the user is logged in with Google OAuth2 with required scopes.
"""

import asyncio
import os
from typing import List, Optional

import streamlit as st
from httpx_oauth.clients.google import GoogleOAuth2
from httpx_oauth.exceptions import GetIdEmailError
from httpx_oauth.oauth2 import OAuth2Token


async def write_authorization_url(
    client: GoogleOAuth2, redirect_uri: str, scopes: Optional[List[str]] = None
) -> str:
    """
    Generates and returns the authorization URL.

    Args:
        client: GoogleOAuth2 client.
        redirect_uri: URI to redirect to after authorization.

    Returns:
        The authorization URL.
    """
    if scopes is None:
        scopes = [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        ]

    authorization_url = await client.get_authorization_url(
        redirect_uri,
        scope=scopes,
        extras_params={
            "access_type": "offline",
            "prompt": "select_account",
        },
    )
    return authorization_url


async def get_access_token(
    client: GoogleOAuth2, redirect_uri: str, code: str
) -> OAuth2Token:
    """
    Exchanges the authorization code for an access token.

    Args:
        client: GoogleOAuth2 client.
        redirect_uri: URI to redirect to after authorization.
        code: Authorization code received from Google.

    Returns:
        The OAuth2Token object.
    """
    token = await client.get_access_token(code, redirect_uri)
    return token


async def get_email(client: GoogleOAuth2, token: OAuth2Token) -> tuple[str, str | None]:
    """
    Retrieves user ID and email from the access token.

    Args:
        client: GoogleOAuth2 client.
        token: OAuth2Token object.

    Returns:
        A tuple containing user ID and email.
    """
    try:
        access_token = token["access_token"]
        user_id, user_email = await client.get_id_email(access_token)
        return user_id, user_email
    except GetIdEmailError as e:
        print(f"Error retrieving email: {e.response.json()}")
        raise e


def _display_login_prompt(authorization_url: str, error_message: str | None = None):
    """
    Displays a login prompt with a link to the authorization URL.

    Args:
        authorization_url: The URL to redirect the user to for authorization.
        error_message: Optional error message to display.
    """
    if error_message:
        st.error(error_message)
    st.write(
        f"""
        <h1>Please login using this <a target="_self" href="{authorization_url}">url</a></h1>
        """,
        unsafe_allow_html=True,
    )


def google_oauth2_required(scopes: Optional[List[str]] = None):
    """
    Decorator to check if the user is logged in with Google OAuth2 with required scopes.

    If the user is logged in, the decorated function is executed.
    Otherwise, a login prompt is displayed.

    Args:
        scopes: List of Google API scopes to request during authentication.
    """

    def decorator(func):
        """
        Decorator to check if the user is logged in with Google OAuth2 with required scopes.
        """
        def wrapper(*args, **kwargs):
            # Get the environment variables
            client_id = os.getenv("GOOGLE_CLIENT_ID")
            client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
            redirect_uri = os.getenv("REDIRECT_URI")
            if not client_id or not client_secret or not redirect_uri:
                raise ValueError(
                    "GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and REDIRECT_URI must be set"
                )

            # Get the token from the query params if it exists
            client = GoogleOAuth2(client_id, client_secret)
            token: Optional[OAuth2Token] = st.session_state.get("token", None)
            if token is None:
                code = st.query_params.get("code")
                if code:
                    try:
                        token = asyncio.run(
                            get_access_token(
                                client=client, redirect_uri=redirect_uri, code=code
                            )
                        )
                        st.session_state.token = token
                    # pylint: disable=broad-exception-caught
                    except Exception:
                        authorization_url = asyncio.run(
                            write_authorization_url(
                                client=client, redirect_uri=redirect_uri, scopes=scopes
                            )
                        )
                        _display_login_prompt(
                            authorization_url,
                            error_message="This account is not allowed or page was refreshed. Please try again.",
                        )
                        return None
                else:
                    authorization_url = asyncio.run(
                        write_authorization_url(
                            client=client, redirect_uri=redirect_uri, scopes=scopes
                        )
                    )
                    _display_login_prompt(authorization_url)
                    return None
            # Check if the token is expired
            if token and token.is_expired():
                authorization_url = asyncio.run(
                    write_authorization_url(
                        client=client, redirect_uri=redirect_uri, scopes=scopes
                    )
                )
                _display_login_prompt(
                    authorization_url,
                    error_message="Login session has ended, please login again.",
                )
                st.session_state.token = None
                return None
            if token:
                st.session_state.token = token
                user_id, user_email = asyncio.run(get_email(client=client, token=token))
                st.session_state.user_id = user_id
                st.session_state.user_email = user_email
                return func(*args, **kwargs)
            return None

        return wrapper

    return decorator
