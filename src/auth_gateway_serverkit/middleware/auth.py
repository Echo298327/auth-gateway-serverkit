from fastapi import HTTPException, Request, Depends, status
from typing import Callable, Any
from functools import wraps
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID
from .config import settings as auth_settings
from ..keycloak.manager import get_client_secret
from .schemas import UserPayload
import requests
import jwt
from ..logger import init_logger

# Set up OAuth2 (the tokenUrl can be set later when settings are initialized)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='None')
logger = init_logger("serverkit.middleware.auth")


def get_keycloak_openid():
    keycloak_openid = KeycloakOpenID(
        server_url=auth_settings.SERVER_URL,
        client_id=auth_settings.CLIENT_ID,
        realm_name=auth_settings.REALM,
        verify=True
    )
    return keycloak_openid


async def get_idp_public_key():
    keycloak_openid = get_keycloak_openid()
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        f"{keycloak_openid.public_key()}\n"
        "-----END PUBLIC KEY-----"
    )


async def get_payload(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Get the payload from the token.

    :param token: User's access token.
    :return: Decoded token payload.
    """
    try:
        key = await get_idp_public_key()
        audience = auth_settings.CLIENT_ID
        decoded_token = jwt.decode(
            token,
            key=key,
            algorithms=['RS256'],
            audience=audience,
            leeway=0  # Ensure no leeway is applied
        )
        return decoded_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidAudienceError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid audience: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def get_user_info(token: str = Depends(oauth2_scheme)) -> UserPayload:
    """
    Get user information from the token.

    :param token: User's access token.
    :return: User's information.
    """
    try:
        payload = await get_payload(token)
        return UserPayload(
            id=payload.get("sub"),
            # username=payload.get("preferred_username"),
            # email=payload.get("email"),
            # first_name=payload.get("given_name"),
            # last_name=payload.get("family_name"),
            realm_roles=payload.get("realm_access", {}).get("roles", []),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Error getting user info: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def check_entitlement(token: str, resource_id: str) -> bool:
    """
    Check if the token has access to a specific resource and scope in Keycloak.

    :param token: User's access token.
    :param resource_id: Resource to check access for (e.g., API endpoint).
    :return: True if access is granted, False otherwise.
    """
    try:
        if not auth_settings.CLIENT_SECRET:
            client_secret = await get_client_secret()
            if not client_secret:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to get client secret"
                )
            auth_settings.CLIENT_SECRET = client_secret

        token_url = f"{auth_settings.SERVER_URL}/realms/{auth_settings.REALM}/protocol/openid-connect/token"
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Bearer {token}',
        }
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
            'client_id': auth_settings.CLIENT_ID,
            'client_secret': auth_settings.CLIENT_SECRET,
            'audience': auth_settings.CLIENT_ID,
            'permission': resource_id,
        }
        response = requests.post(token_url, data=data, headers=headers, verify=True)
        if response.status_code == 200 and 'access_token' in response.json():
            return True
        else:
            logger.error(response.json())
            return False

    except Exception as e:
        logger.error(f"Error checking entitlement: {str(e)}")
        return False


def auth(get_user_by_uid: Callable[[str], Any]):
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authorization token missing"
                )
            token = token.replace("Bearer ", "")
            key_user = await get_user_info(token)
            service = kwargs.get("service")
            action = kwargs.get("action")
            resource = service + "/" + action

            # Verify that the user has the permission to execute the request
            is_entitled = await check_entitlement(token, resource)
            if not is_entitled:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

            user = await get_user_by_uid(key_user.id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            request.state.user = user

            # Call the original function if authorization is successful
            return await func(request, *args, **kwargs)

        return wrapper

    return decorator
