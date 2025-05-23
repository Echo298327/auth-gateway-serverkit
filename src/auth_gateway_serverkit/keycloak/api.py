import os
import json
import aiohttp
from .config import settings
from ..logger import init_logger

logger = init_logger("serverkit.keycloak.api")


async def get_resource_id(resource_name, admin_token, client_uuid) -> str | None:
    """
    Retrieve the resource ID for a given resource name.
    :param resource_name:
    :param admin_token:
    :param client_uuid:
    :return: Resource ID if found, None otherwise
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/resource"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    resources = await response.json()
                    for resource in resources:
                        if resource['name'] == resource_name:
                            return resource['_id']
                else:
                    logger.error(f"Failed to fetch resources. Status: {response.status}, Response: {await response.text()}")
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while retrieving resource ID for '{resource_name}': {e}")
    return None


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


async def get_assigned_client_scopes(admin_token, client_uuid) -> list:
    """
    Retrieve default and optional client scopes assigned to a particular client.
    :param admin_token:
    :param client_uuid:
    :return: List of assigned client scopes
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    # Endpoint to list all scopes assigned to a client
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/default-client-scopes"

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.json()
            else:
                logger.error(
                    f"Failed to retrieve default client scopes. "
                    f"Status: {response.status}, Response: {await response.text()}"
                )
                return []


async def get_optional_client_scopes(admin_token, client_uuid) -> list:
    """
    Retrieve optional client scopes assigned to a particular client.
    :param admin_token:
    :param client_uuid:
    :return: List of optional client scopes
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/optional-client-scopes"

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                return await response.json()
            else:
                logger.error(
                    f"Failed to retrieve optional client scopes. "
                    f"Status: {response.status}, Response: {await response.text()}"
                )
                return []


async def remove_default_scopes(admin_token, client_uuid, scopes_to_remove=None) -> bool:
    """
    Removes specified scopes (e.g. 'email', 'profile', 'roles') from both
    default and optional client scopes.
    :param admin_token: Admin token for authentication
    :param client_uuid: UUID of the client
    :param scopes_to_remove: Set of scopes to remove
    :return: True if successful, False otherwise
    """
    if scopes_to_remove is None:
        scopes_to_remove = {"email", "profile"}

    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    base_url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}"

    # 1. Retrieve default client scopes
    default_scopes = await get_assigned_client_scopes(admin_token, client_uuid)
    # 2. Retrieve optional client scopes
    optional_scopes = await get_optional_client_scopes(admin_token, client_uuid)

    success = True

    async with aiohttp.ClientSession() as session:
        # Remove from default scopes
        for scope in default_scopes:
            if scope["name"] in scopes_to_remove:
                scope_id = scope["id"]
                remove_url = f"{base_url}/default-client-scopes/{scope_id}"
                async with session.delete(remove_url, headers=headers) as resp:
                    if resp.status == 204:
                        logger.info(f"Removed default client scope '{scope['name']}' successfully.")
                    else:
                        logger.error(
                            f"Failed to remove default client scope '{scope['name']}'. "
                            f"Status: {resp.status}, Response: {await resp.text()}"
                        )
                        success = False

        # Remove from optional scopes
        for scope in optional_scopes:
            if scope["name"] in scopes_to_remove:
                scope_id = scope["id"]
                remove_url = f"{base_url}/optional-client-scopes/{scope_id}"
                async with session.delete(remove_url, headers=headers) as resp:
                    if resp.status == 204:
                        logger.info(f"Removed optional client scope '{scope['name']}' successfully.")
                    else:
                        logger.error(
                            f"Failed to remove optional client scope '{scope['name']}'. "
                            f"Status: {resp.status}, Response: {await resp.text()}"
                        )
                        success = False

    return success


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
                    logger.info(f"Realm '{settings.REALM}' already exists")
                    return True
                else:
                    logger.error(f"Failed to create realm. Status: {response.status}, Response: {await response.text()}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating realm: {e}")
        return False


async def create_client(admin_token) -> bool:
    """
    Create a new client in Keycloak.
    :param admin_token:
    :return: True if successful, False otherwise
    """

    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients"
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    payload = {
        'clientId': settings.CLIENT_ID,
        'name': settings.CLIENT_ID,
        'enabled': True,
        'publicClient': False,  # Must be False for Authorization Services
        'protocol': 'openid-connect',
        'redirectUris': ['*'],  # Update based on your app's requirements
        'webOrigins': ['*'],
        'directAccessGrantsEnabled': True,
        'serviceAccountsEnabled': True,  # REQUIRED for Authorization Services
        'standardFlowEnabled': True,
        'implicitFlowEnabled': False,
        'authorizationServicesEnabled': True,  # Enable Authorization Services
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Client '{settings.CLIENT_ID}' created successfully")
                    return True
                elif response.status == 409:
                    logger.info(f"Client '{settings.CLIENT_ID}' already exists")
                    return True
                else:
                    logger.error(f"Failed to create client. Status: {response.status}, Response: {await response.text()}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating client: {e}")
        return False


async def create_realm_roles(admin_token) -> bool:
    """
    Create realm roles in Keycloak based on the configuration file.
    :param admin_token:
    :return: True if successful, False otherwise
    """
    config_path = os.path.join(os.getcwd(), "keycloak_config.json")
    if not os.path.exists(config_path):
        logger.error("Configuration file not found")
        return False

    with open(config_path, 'r') as file:
        config = json.load(file)

    roles_to_create = config.get("realm_roles", [])
    if not roles_to_create:
        logger.warning("No realm roles defined in the configuration")
        return True  # Nothing to create, but not a failure

    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    success = True
    for role in roles_to_create:
        url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/roles"
        payload = {
            'name': role['name'],
            'description': role.get('description', ''),
            'composite': False,
            'clientRole': False
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload) as response:
                    if response.status == 201:
                        logger.info(f"Role '{role['name']}' created successfully in realm '{settings.REALM}'")
                    elif response.status == 409:
                        logger.info(f"Role '{role['name']}' already exists in realm '{settings.REALM}'")
                        # Optionally update the role description if it already exists
                        # await update_role_description(role['name'], role.get('description', ''), headers)
                    else:
                        logger.error(f"Failed to create role '{role['name']}'. Status: {response.status}, Response: {await response.text()}")
                        success = False
        except aiohttp.ClientError as e:
            logger.error(f"Connection error while creating role '{role['name']}': {e}")
            success = False

    return success


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
        "editUsernameAllowed": True  # Enable editing the username
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


async def add_audience_protocol_mapper(admin_token) -> bool:
    """
    Add an audience protocol mapper to the client in Keycloak.
    :param admin_token:
    :return: True if successful, False otherwise
    """

    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }

    # First, get the client ID (UUID) for your client
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients?clientId={settings.CLIENT_ID}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    clients = await response.json()
                    if clients:
                        client_uuid = clients[0]['id']
                    else:
                        logger.error(f"Client '{settings.CLIENT_ID}' not found")
                        return False
                else:
                    logger.error(f"Failed to retrieve client. Status: {response.status}, Response: {await response.text()}")
                    return False

            # Now, add the Protocol Mapper to the client
            url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/protocol-mappers/models"
            payload = {
                "name": "audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.client.audience": settings.CLIENT_ID,
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "aud",
                    "userinfo.token.claim": "false"
                }
            }
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Audience Protocol Mapper added successfully to client '{settings.CLIENT_ID}'")
                    return True
                elif response.status == 409:
                    logger.info(f"Audience Protocol Mapper already exists for client '{settings.CLIENT_ID}'")
                    return True
                else:
                    logger.error(f"Failed to add Audience Protocol Mapper. Status: {response.status}, Response: {await response.text()}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while adding Audience Protocol Mapper: {e}")
        return False


async def create_policy(policy_name, description, roles, admin_token, client_uuid) -> bool:
    """
    Create a new policy in Keycloak.
    :param policy_name:
    :param description:
    :param roles:
    :param admin_token:
    :param client_uuid:
    :return: True if successful, False otherwise
    """

    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/policy/role"
    payload = {
        "name": policy_name,
        "description": description,
        "logic": "POSITIVE",
        "roles": [{"id": role} for role in roles]
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Policy '{policy_name}' created successfully")
                elif response.status == 409:
                    logger.info(f"Policy '{policy_name}' already exists")
                else:
                    logger.error(f"Failed to create policy '{policy_name}'. Status: {response.status}, Response: {await response.text()}")
                return response.status == 201 or response.status == 409
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating policy '{policy_name}': {e}")
        return False


async def create_permission(permission_name, description, policies, resource_ids, admin_token, client_uuid) -> bool:
    """
    Create a new permission in Keycloak.
    :param permission_name:
    :param description:
    :param policies:
    :param resource_ids:
    :param admin_token:
    :param client_uuid:
    :return: True if successful, False otherwise
    """

    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/permission/resource"
    payload = {
        "name": permission_name,
        "description": description,
        "type": "resource",
        "resources": resource_ids,
        "policies": policies
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Permission '{permission_name}' created successfully")
                elif response.status == 409:
                    logger.info(f"Permission '{permission_name}' already exists")
                else:
                    logger.error(f"Failed to create permission '{permission_name}'. Status: {response.status}, Response: {await response.text()}")
                return response.status == 201 or response.status == 409
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating permission '{permission_name}': {e}")
        return False


async def create_resource(resource_name, display_name, url,admin_token, client_uuid) -> bool:
    """
    Create a new resource in Keycloak.
    :param resource_name:
    :param display_name:
    :param url:
    :param admin_token:
    :param client_uuid:
    :return: True if successful, False otherwise
    """

    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    resource_url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/resource"
    payload = {
        "owner": None,
        "name": resource_name,
        "displayName": display_name,
        "uri": url,
        "type": "REST API",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(resource_url, headers=headers, json=payload) as response:
                if response.status == 201:
                    logger.info(f"Resource '{resource_name}' created successfully")
                elif response.status == 409:
                    logger.info(f"Resource '{resource_name}' already exists")
                else:
                    logger.error(f"Failed to create resource '{resource_name}'. Status: {response.status}, Response: {await response.text()}")
                return response.status == 201 or response.status == 409
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating resource '{resource_name}': {e}")
        return False
