from typing import Optional, Dict, List, Union
from ..aiohttp_client import get, post, put, delete
from ..logger import init_logger
from .config import settings
from .api import get_admin_token, get_client_secret

logger = init_logger("serverkit.keycloak.manager")

server_url = settings.SERVER_URL
client_id = settings.CLIENT_ID
realm = settings.REALM
scope = settings.SCOPE


async def add_user_to_keycloak(
    user_name: str,
    first_name: str,
    last_name: str,
    email: str,
    password: str,
    role_list: List[str]
) -> Dict[str, Union[str, None]]:
    """
    Add a new user to Keycloak with specified roles.
    :param user_name: Username for the new user
    :param first_name: First name of the user
    :param last_name: Last name of the user
    :param email: Email address of the user
    :param password: Password for the user
    :param role_list: List of role names to assign to the user
    :return: Dictionary containing status and user ID or error message
    """
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
        status, response_text, _ = await post(url, json=body, headers=headers)
        if status == 201:
            location_header = response_text.split('\n')[0]  # Get the first line which contains the Location header
            user_uuid = location_header.rstrip('/').split('/')[-1]

            # Step 2: Assign Specified Roles to the New User
            roles_to_assign = []
            for role_name in role_list:
                logger.info(f"Assigning role '{role_name}' to user '{user_name}'")
                roles_url = f"{server_url}/admin/realms/{realm}/roles/{role_name}"
                role_status, role_response_text, role = await get(roles_url, headers=headers)
                if role_status == 200:
                    roles_to_assign.append({
                        "id": role['id'],
                        "name": role['name'],
                        "composite": role.get('composite', False),
                        "clientRole": role.get('clientRole', False),
                        "containerId": role.get('containerId', realm)
                    })
                else:
                    logger.error(f"Error retrieving role '{role_name}': {role_response_text}")
                    return {'status': 'error', 'message': f"Error retrieving role '{role_name}' from Keycloak", "keycloakUserId": user_uuid}

            # Assign the roles to the user
            role_mapping_url = f"{server_url}/admin/realms/{realm}/users/{user_uuid}/role-mappings/realm"
            assign_status, assign_response_text, _ = await post(
                role_mapping_url,
                json={"roles": roles_to_assign},
                headers=headers
            )

            if assign_status == 204:
                # Role assignment successful
                return {'status': 'success', 'keycloakUserId': user_uuid}
            else:
                logger.error(f"Error assigning roles to user: {assign_response_text}")
                return {'status': 'error', 'message': "Error assigning roles to user in Keycloak", "keycloakUserId": user_uuid}
        else:
            logger.error(f"Error creating user in Keycloak: {response_text}, response status: {status}")
            return {'status': 'error', 'message': "Error creating user in Keycloak", "keycloakUserId": None}
    except Exception as e:
        logger.error(f"Error creating user in Keycloak: {e}")
        return {'status': 'error', 'message': "Exception occurred while creating user in Keycloak"}


async def update_user_in_keycloak(
    user_id: str,
    user_name: str,
    first_name: str,
    last_name: str,
    email: str,
    roles: Optional[List[str]] = None,
    password: Optional[str] = None
) -> Dict[str, str]:
    """
    Update an existing user in Keycloak.
    :param user_id: UUID of the user to update
    :param user_name: New username
    :param first_name: New first name
    :param last_name: New last name
    :param email: New email address
    :param roles: Optional list of role names to assign
    :param password: Optional new password
    :return: Dictionary containing status and optional error message
    """
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error obtaining admin token"}

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }

        # Step 1: Update Basic User Info
        body = {
            "username": user_name,
            "firstName": first_name,
            "lastName": last_name,
            "email": email
        }
        url = f"{server_url}/admin/realms/{realm}/users/{user_id}"
        status, response_text, _ = await put(url, json=body, headers=headers)
        if status != 204:
            logger.error(f"Error updating user in Keycloak: {response_text}")
            return {'status': 'error', 'message': "Error updating user in Keycloak"}

        # Step 2: Update User Roles (if roles provided)
        if roles:
            # Retrieve current roles assigned to the user
            current_roles_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
            current_roles_status, current_roles_text, current_roles = await get(current_roles_url, headers=headers)
            if current_roles_status != 200:
                logger.error(f"Error fetching current roles for user: {current_roles_text}")
                return {'status': 'error', 'message': "Error fetching current roles from Keycloak"}

            current_role_names = {role["name"] for role in current_roles}

            # Determine roles to add and remove
            roles_to_add = set(roles) - current_role_names
            roles_to_remove = current_role_names - set(roles)

            # Add new roles
            roles_to_add_details = []
            for role_name in roles_to_add:
                role_url = f"{server_url}/admin/realms/{realm}/roles/{role_name}"
                role_status, role_text, role = await get(role_url, headers=headers)
                if role_status == 200:
                    roles_to_add_details.append({
                        "id": role["id"],
                        "name": role["name"]
                    })
                else:
                    logger.error(f"Error retrieving role '{role_name}': {role_text}")
                    return {'status': 'error', 'message': f"Error retrieving role '{role_name}' from Keycloak"}

            if roles_to_add_details:
                assign_roles_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
                assign_status, assign_text, _ = await post(
                    assign_roles_url,
                    json={"roles": roles_to_add_details},
                    headers=headers
                )
                if assign_status != 204:
                    logger.error(f"Error assigning roles: {assign_text}")
                    return {'status': 'error', 'message': "Error assigning roles in Keycloak"}

            # Remove roles no longer assigned
            roles_to_remove_details = [
                role for role in current_roles if role["name"] in roles_to_remove
            ]
            if roles_to_remove_details:
                remove_roles_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm"
                remove_status, remove_text, _ = await delete(
                    remove_roles_url,
                    headers=headers,
                    json={"roles": roles_to_remove_details}
                )
                if remove_status != 204:
                    logger.error(f"Error removing roles: {remove_text}")
                    return {'status': 'error', 'message': "Error removing roles in Keycloak"}

            logout_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/logout"
            logout_status, logout_text, _ = await post(logout_url, headers=headers)
            if logout_status != 204:
                logger.error(f"Error logging out user: {logout_text}")
                return {'status': 'error', 'message': "Error logging out user from Keycloak"}

        if password:
            # Step 3: Update User Password
            password_body = {
                "type": "password",
                "value": password,
                "temporary": False
            }
            password_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/reset-password"
            password_status, password_text, _ = await put(password_url, json=password_body, headers=headers)
            if password_status != 204:
                logger.error(f"Error updating user password: {password_text}")
                return {'status': 'error', 'message': "Error updating user password in Keycloak"}

        return {'status': 'success'}

    except Exception as e:
        logger.error(f"Error updating user in Keycloak: {e}")
        return {'status': 'error', 'message': "Error updating user in Keycloak"}


async def delete_user_from_keycloak(user_id: str) -> Dict[str, str]:
    """
    Delete a user from Keycloak.
    :param user_id: UUID of the user to delete
    :return: Dictionary containing status and optional error message
    """
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error deleting user from keycloak"}
        headers = {
            "Authorization": f"Bearer {token}"
        }
        url = f"{server_url}/admin/realms/{realm}/users/{user_id}"
        status, response_text, _ = await delete(url, headers=headers)
        if status == 204:
            return {'status': 'success'}
        else:
            logger.error(f"Error deleting user from keycloak: {response_text}")
            return {'status': 'error', 'message': "Error deleting user from keycloak"}
    except Exception as e:
        logger.error(f"Error deleting user from keycloak: {e}")
        return {'status': 'error', 'message': "Error deleting user from keycloak"}


async def execute_actions_email(
    admin_token: str,
    user_id: str,
    actions: Optional[List[str]] = None,
    lifespan: int = 3600,
    redirect_uri: Optional[str] = None,
) -> bool:
    """
    Trigger Keycloak to send an email with specified actions to the user.
    :param admin_token: Admin access token for Keycloak admin API
    :param user_id: The UUID of the user in Keycloak
    :param actions: A list of actions. Common actions: ["VERIFY_EMAIL"], ["UPDATE_PASSWORD"], or both
    :param lifespan: Link expiration time in seconds. Default is 3600 (1 hour)
    :param redirect_uri: Optional. Where to redirect after the action is completed
    :return: True if the email action was triggered successfully, False otherwise
    """
    if actions is None:
        actions = ["UPDATE_PASSWORD"]

    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    # Build query parameters
    query_params = [f"lifespan={lifespan}"]
    if redirect_uri:
        query_params.append(f"redirectUri={redirect_uri}")
    if client_id:
        query_params.append(f"clientId={settings.CLIENT_ID}")

    # Construct the URL for the execute actions endpoint with query parameters
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/users/{user_id}/execute-actions-email"
    if query_params:
        url += "?" + "&".join(query_params)

    # Wrap actions in a dictionary to match expected type
    payload = {"actions": actions}
    status, response_text, _ = await put(url, headers=headers, json=payload)
    if status == 204:
        logger.info("Email action triggered successfully. The user should receive an email.")
        return True
    else:
        logger.error(f"Failed to trigger email action. Status: {status}, Response: {response_text}")
        return False


async def retrieve_client_token(user_name: str, password: str) -> Optional[Dict[str, Union[int, str, dict]]]:
    """
    Retrieve a token from Keycloak using the Resource Owner Password Credentials Grant.
    :param user_name: The username of the user
    :param password: The password of the user
    :return: Dictionary containing status, response text, and JSON response if successful, None otherwise
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

        url = f"{server_url}/realms/{realm}/protocol/openid-connect/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = {
            "username": user_name,
            "password": password,
            "grant_type": "password",
            "scope": scope,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        status, response_text, response_json = await post(url, data=payload, headers=headers)
        return {'status': status, 'text': response_text, 'json': response_json}
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None
