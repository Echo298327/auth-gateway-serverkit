"""Keycloak Realm Module for the auth gateway serverkit."""
import aiohttp
from .config import settings
from ..logger import init_logger

logger = init_logger(__name__)


async def create_realm(admin_token) -> bool:
    """
    Create a new realm in Keycloak.
    :param admin_token:
    :return: True if successful, False otherwise
    """

    url = f"{settings.SERVER_URL}/admin/realms"
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    payload = {
        'realm': settings.REALM,
        'enabled': True,
        'accessTokenLifespan': 36000,  # Set token lifespan to 10 hours (in seconds)
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Realm '{settings.REALM}' created successfully")
                    return True
                elif response.status == 409:
                    return True
                else:
                    logger.error(f"Failed to create realm. Status: {response.status}, Response: {await response.text()}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating realm: {e}")
        return False


async def set_frontend_url(admin_token) -> bool:
    """
    Set the frontend URL for the Keycloak realm.
    :param admin_token:
    :return: True if successful, False otherwise
    """
    frontend_url = settings.KEYCLOAK_FRONTEND_URL
    if not frontend_url:
        logger.error("KEYCLOAK_FRONTEND_URL is not set")
        return False

    headers = {'Authorization': f'Bearer {admin_token}', 'Content-Type': 'application/json'}
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}"
    payload = {'attributes': {'frontendUrl': frontend_url}}
    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, json=payload) as response:
            if response.status == 204:
                logger.info(f"Frontend URL set to {frontend_url}")
                return True
            logger.error(f"Failed to set Frontend URL. Status: {response.status}, Response: {await response.text()}")
            return False


async def enable_edit_username(admin_token) -> bool:
    """
    Enable the option to edit usernames in the Keycloak realm.
    :param admin_token:
    :return: True if successful, False otherwise
    """

    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}"
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    payload = {
        "realm": settings.REALM,
        "editUsernameAllowed": True
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.put(url, headers=headers, json=payload) as response:
                if response.status == 204:
                    logger.info(f"Enabled edit username for realm '{settings.REALM}' successfully")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to enable edit username. Status: {response.status}, Response: {error_text}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while enabling edit username: {e}")
        return False
