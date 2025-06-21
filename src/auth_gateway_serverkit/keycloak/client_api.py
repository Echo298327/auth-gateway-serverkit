"""  Keycloak Client API Module for the auth gateway serverkit."""
import os
import json
import aiohttp
import httpx
from .config import settings
from ..logger import init_logger

logger = init_logger("serverkit.keycloak.api")


async def retrieve_client_token(user_name, password):
    """
    Retrieve a token from Keycloak using the Resource Owner Password Credentials Grant.

    Args:
        user_name (str): The username of the user.
        password (str): The password of the user.

    Returns:
        dict: A dictionary containing the access token and other token details.
    """
    try:
        if settings.CLIENT_SECRET:
            client_secret = settings.CLIENT_SECRET
        else:
            logger.info("Fetching client secret from Keycloak")
            client_secret = await get_client_secret()
            settings.CLIENT_SECRET = client_secret
            if not client_secret:
                logger.error("Failed to get client secret")
                return None

        url = f"{settings.SERVER_URL}/realms/{settings.REALM}/protocol/openid-connect/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "username": user_name,
            "password": password,
            "grant_type": "password",
            "scope": "openid",
            "client_id": settings.CLIENT_ID,
            "client_secret": client_secret,
        }
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, data=payload, headers=headers)
            return response
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None


async def get_admin_token() -> str | None:
    """
    Retrieve an admin token from Keycloak using the bootstrap admin credentials.
    :return: Access token if successful, None otherwise
    """
    url = f"{settings.SERVER_URL}/realms/master/protocol/openid-connect/token"
    payload = {
        'username': settings.KC_BOOTSTRAP_ADMIN_USERNAME,
        'password': settings.KC_BOOTSTRAP_ADMIN_PASSWORD,
        'grant_type': 'password',
        'client_id': 'admin-cli'
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['access_token']
                else:
                    logger.error(f"Failed to get admin token. Status: {response.status}, Response: {await response.text()}")
                    return None
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while getting admin token: {e}")
        return None


async def get_client_uuid(admin_token) -> str | None:
    """
    Retrieve the UUID of the client with the specified clientId from Keycloak.
    :param admin_token:
    :return: Client UUID if found, None otherwise
    """
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients?clientId={settings.CLIENT_ID}"
    headers = {'Authorization': f'Bearer {admin_token}', 'Content-Type': 'application/json'}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                clients = await response.json()
                if clients:
                    return clients[0]['id']  # UUID of the client
            logger.error(f"Failed to find client UUID for clientId '{settings.CLIENT_ID}'. Status: {response.status}")
            return None


async def get_client_secret() -> str | None:
    """
    Retrieve the client secret for the specified client in Keycloak.
    This function first obtains an admin token, then retrieves the client UUID,
    and finally fetches the client secret using the UUID.
    :return: Client secret if found, None otherwise
    """
    try:
        # Step 1: Obtain the admin token
        admin_token = await get_admin_token()
        if not admin_token:
            logger.error("Unable to obtain admin token.")
            return None

        # Step 2: Retrieve the client UUID using the existing get_client_uuid function
        client_uuid = await get_client_uuid(admin_token)
        if not client_uuid:
            logger.error(f"Unable to retrieve UUID for client_id: {settings.CLIENT_ID}")
            return None

        # Step 3: Fetch the client secret using the client UUID
        secret_url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/client-secret"
        headers = {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        }
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
            async with session.get(secret_url, headers=headers) as secret_response:
                if secret_response.status == 200:
                    secret_data = await secret_response.json()
                    client_secret = secret_data.get('value')

                    if not client_secret:
                        logger.error("Client secret not found in the response.")
                        return None

                    return client_secret
                else:
                    response_text = await secret_response.text()
                    logger.error(f"Error fetching client secret: {response_text}")
                    return None

    except aiohttp.ClientError as e:
        logger.error(f"HTTP ClientError occurred while retrieving client secret: {e}")
        return None
    except Exception as e:
        logger.error(f"Exception occurred while retrieving client secret: {e}")
        return None


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
                    return True
                else:
                    logger.error(f"Failed to create client. Status: {response.status}, Response: {await response.text()}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating client: {e}")
        return False


async def create_realm_roles(admin_token) -> bool:
    """
    Create realm roles in Keycloak based on the authorization configuration.
    :param admin_token:
    :return: True if successful, False otherwise
    """
    authorization_dir = os.path.join(os.getcwd(), "authorization")
    roles_file = os.path.join(authorization_dir, "roles.json")
    
    if not os.path.exists(roles_file):
        logger.error("roles.json file not found in authorization directory")
        return False

    with open(roles_file, 'r') as file:
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
                        pass  # Role already exists
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
                    return True
                else:
                    logger.error(f"Failed to add Audience Protocol Mapper. Status: {response.status}, Response: {await response.text()}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while adding Audience Protocol Mapper: {e}")
        return False


async def get_role_ids_by_names(role_names, admin_token) -> list:
    """
    Get role IDs by role names from Keycloak.
    :param role_names: List of role names
    :param admin_token: Admin token for authentication
    :return: List of role IDs
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    
    role_ids = []
    for role_name in role_names:
        url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/roles/{role_name}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        role_data = await response.json()
                        role_ids.append(role_data['id'])
                    else:
                        logger.error(f"Failed to get role ID for '{role_name}'. Status: {response.status}")
                        return []
        except aiohttp.ClientError as e:
            logger.error(f"Connection error while getting role ID for '{role_name}': {e}")
            return []
    
    return role_ids


async def create_policy(policy_name, description, roles, admin_token, client_uuid) -> bool:
    """
    Create a new policy in Keycloak.
    :param policy_name:
    :param description:
    :param roles: List of role names
    :param admin_token:
    :param client_uuid:
    :return: True if successful, False otherwise
    """
    
    # Convert role names to role IDs
    role_ids = await get_role_ids_by_names(roles, admin_token)
    if not role_ids:
        logger.error(f"Failed to get role IDs for policy '{policy_name}'")
        return False

    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/policy/role"
    payload = {
        "name": policy_name,
        "description": description,
        "logic": "POSITIVE",
        "roles": [{"id": role_id} for role_id in role_ids]
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 201 or response.status == 409:
                    return True
                else:
                    logger.error(f"Failed to create policy '{policy_name}'. Status: {response.status}, Response: {await response.text()}")
                    return False
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
                if response.status == 201 or response.status == 409:
                    return True
                else:
                    logger.error(f"Failed to create permission '{permission_name}'. Status: {response.status}, Response: {await response.text()}")
                    return False
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
                if response.status == 201 or response.status == 409:
                    return True
                else:
                    logger.error(f"Failed to create resource '{resource_name}'. Status: {response.status}, Response: {await response.text()}")
                    return False
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while creating resource '{resource_name}': {e}")
        return False



