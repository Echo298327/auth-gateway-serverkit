"""Keycloak server initialization module for the auth gateway serverkit."""
import os
import asyncio
import aiohttp
from ..logger import init_logger
from .config import settings
from .client_api import (
    get_admin_token, get_client_uuid, create_realm, set_frontend_url, create_client, create_realm_roles,
    add_audience_protocol_mapper, enable_edit_username, remove_default_scopes
)
from .authorization_api import KeycloakAuthorizationAPI

logger = init_logger("serverkit.keycloak.initializer")


async def check_keycloak_connection():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(settings.SERVER_URL) as response:
                if response.status == 200:
                    logger.info("Successfully connected to Keycloak server")
                    return True
                else:
                    logger.error(f"Failed to connect to Keycloak server. Status: {response.status}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Failed to connect to Keycloak server: {e}")
        return False


async def sync_authorization_configuration():
    """Sync authorization configuration using your existing API module"""

    config_path = os.path.join(os.getcwd(), "keycloak_config.json")
    if not os.path.exists(config_path):
        logger.error("Configuration file not found")
        return False

    try:
        # Use your existing KeycloakAuthorizationAPI
        auth_api = KeycloakAuthorizationAPI()
        success = await auth_api.sync_configuration(config_path)

        if success:
            logger.info("Authorization configuration synced successfully")
        else:
            logger.error("Failed to sync authorization configuration")

        return success

    except Exception as e:
        logger.error(f"Error syncing authorization configuration: {e}")
        return False


async def initialize_keycloak_server(max_retries=30, retry_delay=5):
    # 1) wait until Keycloak is up
    for attempt in range(1, max_retries + 1):
        if await check_keycloak_connection():
            break
        logger.warning(f"Attempt {attempt}/{max_retries} failed. Retrying in {retry_delay}s…")
        await asyncio.sleep(retry_delay)
    else:
        logger.error("Failed to initialize Keycloak after multiple attempts")
        return False

    # 2) get admin token
    admin_token = await get_admin_token()
    if not admin_token:
        logger.error("Failed to get admin token")
        return False

    # 3) run all the "realm & client setup" steps in order
    steps = [
        (create_realm, (),                   "create realm"),
        (set_frontend_url, (),               "set Frontend URL"),
        (create_client, (),                  "create client"),
        (create_realm_roles, (),             "create realm roles"),
        (add_audience_protocol_mapper, (),   "add Audience Protocol Mapper"),
        (enable_edit_username, (),           "enable edit username"),
    ]
    for func, args, desc in steps:
        ok = await func(admin_token, *args)
        if not ok:
            logger.error(f"Failed to {desc}")
            return False

    # 4) fetch the client UUID
    client_uuid = await get_client_uuid(admin_token)
    if not client_uuid:
        logger.error("Failed to get client UUID")
        return False

    # 5) remove scopes and sync authorization configuration
    post_steps = [
        (remove_default_scopes,           (client_uuid,), "remove unwanted default/optional scopes"),
        (sync_authorization_configuration, (),           "sync authorization configuration"),
    ]
    for func, args, desc in post_steps:
        ok = await func(*args)
        if not ok:
            logger.error(f"Failed to {desc}")
            return False

    logger.info("Keycloak initialization completed successfully")
    return True