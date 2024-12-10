import httpx
import json
import aiohttp
from ..logger import init_logger
from .config import settings


logger = init_logger("serverkit.keycloak.manager")

server_url = settings.SERVER_URL
client_id = settings.CLIENT_ID
realm = settings.REALM
scope = settings.SCOPE
admin_username = settings.KC_BOOTSTRAP_ADMIN_USERNAME
admin_password = settings.KC_BOOTSTRAP_ADMIN_PASSWORD


async def retrieve_token(username, password):
    try:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        body = {
            "client_id": client_id,
            # "client_secret": client_secret,
            "scope": scope,
            "username": username,
            "password": password,
            "grant_type": "password"
        }
        url = f"{server_url}/realms/{realm}/protocol/openid-connect/token"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, data=body, headers=headers)
            if response.status_code == 200:
                token = response.json().get('access_token')
                return token
            else:
                logger.error(f"Error retrieving token: {response.text}")
                return None
    except Exception as e:
        logger.error(f"Error retrieving token: {e}")
        return None


async def get_admin_token():
    url = f"{server_url}/realms/master/protocol/openid-connect/token"
    payload = {
        'username': admin_username,
        'password': admin_password,
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


async def get_client_uuid(admin_token):
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


async def get_client_secret():
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


async def add_user_to_keycloak(user_name, first_name, last_name, email: str, password: str, role_list: list):
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error obtaining admin token"}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }

        # Step 1: Create the User
        body = {
            "username": user_name,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": True,
            "emailVerified": True,
            "email": email,
            "credentials": [{"type": "password", "value": password, "temporary": False}]
        }
        url = f"{server_url}/admin/realms/{realm}/users"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, json=body, headers=headers)
            if response.status_code == 201:
                location_header = response.headers.get('Location')
                user_uuid = location_header.rstrip('/').split('/')[-1]

                # Step 2: Assign Specified Roles to the New User
                roles_to_assign = []
                for role_name in role_list:
                    logger.info(f"Assigning role '{role_name}' to user '{user_name}'")
                    roles_url = f"{server_url}/admin/realms/{realm}/roles/{role_name}"
                    role_response = await client.get(roles_url, headers=headers)
                    if role_response.status_code == 200:
                        role = role_response.json()
                        roles_to_assign.append({
                            "id": role['id'],
                            "name": role['name'],
                            "composite": role.get('composite', False),
                            "clientRole": role.get('clientRole', False),
                            "containerId": role.get('containerId', realm)
                        })
                    else:
                        logger.error(f"Error retrieving role '{role_name}': {role_response.text}")
                        return {'status': 'error', 'message': f"Error retrieving role '{role_name}' from Keycloak", "keycloakUserId": user_uuid}

                # Assign the roles to the user
                role_mapping_url = f"{server_url}/admin/realms/{realm}/users/{user_uuid}/role-mappings/realm"
                assign_role_response = await client.post(
                    role_mapping_url,
                    json=roles_to_assign,
                    headers=headers
                )

                if assign_role_response.status_code == 204:
                    # Role assignment successful
                    return {'status': 'success', 'keycloakUserId': user_uuid}
                else:
                    logger.error(f"Error assigning roles to user: {assign_role_response.text}")
                    return {'status': 'error', 'message': "Error assigning roles to user in Keycloak", "keycloakUserId": user_uuid}
            else:
                logger.error(f"Error creating user in Keycloak: {response.text}, response status: {response.status_code}")
                return {'status': 'error', 'message': "Error creating user in Keycloak", "keycloakUserId": None}
    except Exception as e:
        logger.error(f"Error creating user in Keycloak: {e}")
        return {'status': 'error', 'message': "Exception occurred while creating user in Keycloak"}


async def update_user_in_keycloak(
        user_id,
        user_name,
        first_name,
        last_name,
        email,
        roles: list = None,
        password: str = None
):
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error obtaining admin token"}

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }

        async with httpx.AsyncClient(timeout=20) as client:
            # Step 1: Update Basic User Info
            body = {
                "username": user_name,
                "firstName": first_name,
                "lastName": last_name,
                "email": email
            }
            url = f"{server_url}/admin/realms/{realm}/users/{user_id}"
            response = await client.put(url, json=body, headers=headers)
            if response.status_code != 204:
                logger.error(f"Error updating user in Keycloak: {response.text}")
                return {'status': 'error', 'message': "Error updating user in Keycloak"}

            # Step 2: Update User Roles (if roles provided)
            if roles:
                # Retrieve current roles assigned to the user
                current_roles_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
                current_roles_response = await client.get(current_roles_url, headers=headers)
                if current_roles_response.status_code != 200:
                    logger.error(f"Error fetching current roles for user: {current_roles_response.text}")
                    return {'status': 'error', 'message': "Error fetching current roles from Keycloak"}

                current_roles = current_roles_response.json()
                current_role_names = {role["name"] for role in current_roles}

                # Determine roles to add and remove
                roles_to_add = set(roles) - current_role_names
                roles_to_remove = current_role_names - set(roles)

                # Add new roles
                roles_to_add_details = []
                for role_name in roles_to_add:
                    role_url = f"{server_url}/admin/realms/{realm}/roles/{role_name}"
                    role_response = await client.get(role_url, headers=headers)
                    if role_response.status_code == 200:
                        role = role_response.json()
                        roles_to_add_details.append({
                            "id": role["id"],
                            "name": role["name"]
                        })
                    else:
                        logger.error(f"Error retrieving role '{role_name}': {role_response.text}")
                        return {'status': 'error', 'message': f"Error retrieving role '{role_name}' from Keycloak"}

                if roles_to_add_details:
                    assign_roles_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
                    assign_response = await client.post(assign_roles_url, json=roles_to_add_details, headers=headers)
                    if assign_response.status_code != 204:
                        logger.error(f"Error assigning roles: {assign_response.text}")
                        return {'status': 'error', 'message': "Error assigning roles in Keycloak"}

                # Remove roles no longer assigned
                roles_to_remove_details = [
                    role for role in current_roles if role["name"] in roles_to_remove
                ]
                if roles_to_remove_details:
                    remove_roles_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
                    remove_response = await client.request(
                        method="DELETE",
                        url=remove_roles_url,
                        headers=headers,
                        content=json.dumps(roles_to_remove_details),
                    )
                    if remove_response.status_code != 204:
                        logger.error(f"Error removing roles: {remove_response.text}")
                        return {'status': 'error', 'message': "Error removing roles in Keycloak"}

                logout_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/logout"
                logout_response = await client.post(logout_url, headers=headers)
                if logout_response.status_code != 204:
                    logger.error(f"Error logging out user: {logout_response.text}")
                    return {'status': 'error', 'message': "Error logging out user from Keycloak"}

            if password:
                # Step 3: Update User Password
                password_body = {
                    "type": "password",
                    "value": password,
                    "temporary": False
                }
                password_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/reset-password"
                password_response = await client.put(password_url, json=password_body, headers=headers)
                if password_response.status_code != 204:
                    logger.error(f"Error updating user password: {password_response.text}")
                    return {'status': 'error', 'message': "Error updating user password in Keycloak"}

        return {'status': 'success'}

    except Exception as e:
        logger.error(f"Error updating user in Keycloak: {e}")
        return {'status': 'error', 'message': "Error updating user in Keycloak"}


async def delete_user_from_keycloak(user_id):
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error deleting user from keycloak"}
        headers = {
            "Authorization": f"Bearer {token}"
        }
        url = f"{server_url}/admin/realms/{realm}/users/{user_id}"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.delete(url, headers=headers)
            if response.status_code == 204:
                return {'status': 'success'}
            else:
                logger.error(f"Error deleting user from keycloak: {response.text}")
                return {'status': 'error', 'message': "Error deleting user from keycloak"}
    except Exception as e:
        logger.error(f"Error deleting user from keycloak: {e}")
        return {'status': 'error', 'message': "Error deleting user from keycloak"}


async def execute_actions_email(
        admin_token,
        user_id,
        actions=["UPDATE_PASSWORD"],
        lifespan=3600,
        redirect_uri=None,
):
    """Trigger Keycloak to send an email with specified actions to the user.

    Args:
        admin_token (str): Admin access token for Keycloak admin API.
        user_id (str): The UUID of the user in Keycloak.
        actions (list): A list of actions. Common actions: ["VERIFY_EMAIL"], ["UPDATE_PASSWORD"], or both.
        lifespan (int): Link expiration time in seconds. Default is 3600 (1 hour).
        redirect_uri (str): Optional. Where to redirect after the action is completed.

    Returns:
        bool: True if the email action was triggered successfully, False otherwise.
    """
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    # Construct the URL for the execute actions endpoint
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/users/{user_id}/execute-actions-email"

    # Build query parameters
    params = {
        "lifespan": lifespan
    }

    # You can append redirectUri and clientId if they are needed
    if redirect_uri:
        params["redirectUri"] = redirect_uri
    if client_id:
        params["clientId"] = settings.CLIENT_ID

    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, json=actions, params=params) as response:
            if response.status == 204:
                logger.info("Email action triggered successfully. The user should receive an email.")
                return True
            else:
                error_text = await response.text()
                logger.error(f"Failed to trigger email action. Status: {response.status}, Response: {error_text}")
                return False
