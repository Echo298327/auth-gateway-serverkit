"""Firebase auth middleware for FastAPI applications."""
from fastapi import HTTPException, Request, status
from typing import Callable, Any
from functools import wraps
from firebase_admin import auth as firebase_auth
from auth_gateway_serverkit.logger import init_logger

logger = init_logger(__name__)


async def verify_firebase_token(token: str) -> dict:
    """
    Verify Firebase ID token and return decoded token.

    :param token: Firebase ID token
    :return: Decoded token payload
    """
    try:
        # Verify the ID token
        decoded_token = firebase_auth.verify_id_token(token)
        return decoded_token
    except firebase_auth.ExpiredIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except firebase_auth.InvalidIdTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def get_firebase_uuid(token: str) -> str:
    """
    Get user information from Firebase token.

    :param token: Firebase ID token
    :return: User's information
    """
    try:
        payload = await verify_firebase_token(token)

        # Extract user information from Firebase token
        # Firebase tokens have different structure than Keycloak
        user_id = str(payload.get("uid"))  # Firebase uses 'uid' instead of 'sub'

        return user_id

    except Exception as ex:
        logger.error(f"Error getting Firebase user info: {str(ex)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"}
        )


def auth(get_user_by_uid: Callable[[str], Any]):
    """
    Firebase authentication decorator.

    :param get_user_by_uid: Function to get user by Firebase UID
    :return: Decorator function
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # Extract token from Authorization header
            token = request.headers.get("Authorization")
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authorization token missing"
                )

            # Remove 'Bearer ' prefix
            token = token.replace("Bearer ", "")

            # Verify token and get user info
            user_uuid = await get_firebase_uuid(token)

            # Get user from database using Firebase UID
            user = await get_user_by_uid(user_uuid)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

            # Add user to request state
            request.state.user = user

            # Call the original function if authentication is successful
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator