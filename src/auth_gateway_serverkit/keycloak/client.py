"""Keycloak Client Module for the auth gateway serverkit."""
import aiohttp
import httpx
from .config import settings
from ..logger import init_logger

logger = init_logger(__name__)


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


async def refresh_client_token(refresh_token: str):
    """
    Refresh an access token using a Keycloak refresh token.

    Args:
        refresh_token (str): The refresh token from a previous login.

    Returns:
        httpx.Response: Response from Keycloak token endpoint, or None on error.
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
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.CLIENT_ID,
            "client_secret": client_secret,
        }
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, data=payload, headers=headers)
            return response
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None


async def revoke_client_token(refresh_token: str):
    """
    Revoke a refresh token at Keycloak (logout). The token can no longer be used.

    Args:
        refresh_token (str): The refresh token to revoke.

    Returns:
        httpx.Response: Response from Keycloak revoke endpoint, or None on error.
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

        url = f"{settings.SERVER_URL}/realms/{settings.REALM}/protocol/openid-connect/revoke"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = {
            "token": refresh_token,
            "token_type_hint": "refresh_token",
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
        admin_token = await get_admin_token()
        if not admin_token:
            logger.error("Unable to obtain admin token.")
            return None

        client_uuid = await get_client_uuid(admin_token)
        if not client_uuid:
            logger.error(f"Unable to retrieve UUID for client_id: {settings.CLIENT_ID}")
            return None

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

    default_scopes = await get_assigned_client_scopes(admin_token, client_uuid)
    optional_scopes = await get_optional_client_scopes(admin_token, client_uuid)

    success = True

    async with aiohttp.ClientSession() as session:
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
