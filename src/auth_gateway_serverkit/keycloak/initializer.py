import os
import json
import asyncio
import aiohttp
from ..logger import init_logger
from .config import settings
from .manager import get_admin_token, get_client_uuid
from .api import (
    create_realm, set_frontend_url, create_client, create_realm_roles, add_audience_protocol_mapper,
    enable_edit_username, remove_default_scopes, create_resource,
    create_policy, create_permission, get_resource_id
)


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


async def process_json_config(admin_token, client_uuid):
    config_path = os.path.join(os.getcwd(), "keycloak_config.json")
    if not os.path.exists(config_path):
        logger.error("Configuration file not found")
        return False

    with open(config_path, 'r') as file:
        config = json.load(file)

    # Step 1: Create resources and collect their IDs
    resource_ids = {}
    for resource in config.get("resources", []):
        success = await create_resource(
            resource['name'],
            resource['displayName'],
            resource['url'],
            admin_token,
            client_uuid
        )
        if not success:
            logger.error(f"Failed to create resource: {resource['name']}")
            return False

        # Retrieve resource ID from Keycloak
        resource_id = await get_resource_id(resource['name'], admin_token, client_uuid)
        if resource_id:
            resource_ids[resource['name']] = resource_id
        else:
            logger.error(f"Failed to retrieve resource ID for: {resource['name']}")
            return False

    # Step 2: Create policies
    for policy in config.get("policies", []):
        success = await create_policy(
            policy['name'],
            policy['description'],
            policy['roles'],
            admin_token,
            client_uuid
        )
        if not success:
            logger.error(f"Failed to create policy: {policy['name']}")
            return False

    # Step 3: Create permissions and associate them with resources
    for permission in config.get("permissions", []):
        resource_names = permission.get('resources', [])
        if not resource_names:
            logger.error(f"No resources specified for permission '{permission['name']}'")
            return False

        # Get resource IDs for all associated resources
        resource_ids_list = [resource_ids.get(name) for name in resource_names]
        if None in resource_ids_list:
            missing_resources = [name for name, rid in zip(resource_names, resource_ids_list) if rid is None]
            logger.error(f"Missing resource IDs for: {missing_resources}")
            return False

        success = await create_permission(
            permission['name'],
            permission['description'],
            permission['policies'],
            resource_ids_list,  # Pass list of resource IDs
            admin_token,
            client_uuid
        )
        if not success:
            logger.error(f"Failed to create permission: {permission['name']}")
            return False

    return True


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

    # 3) run all the “realm & client setup” steps in order
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

    # 5) remove scopes and process JSON config
    post_steps = [
        (remove_default_scopes,    (client_uuid,), "remove unwanted default/optional scopes"),
        (process_json_config,      (client_uuid,), "process JSON configuration"),
    ]
    for func, args, desc in post_steps:
        ok = await func(admin_token, *args)
        if not ok:
            logger.error(f"Failed to {desc}")
            return False

    logger.info("Keycloak initialization completed successfully")
    return True
