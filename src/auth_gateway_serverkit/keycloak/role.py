"""Keycloak Role Module for the auth gateway serverkit."""
import os
import json
import httpx
import aiohttp
from .config import settings
from ..logger import init_logger
from .client import get_admin_token

logger = init_logger(__name__)


async def get_all_roles() -> dict:
    """
    Fetch all roles from Keycloak.
    This function retrieves all roles defined in the Keycloak realm specified in the settings.
    :return: A dictionary containing the status and roles or an error message.
    """
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error obtaining admin token"}
        headers = {
            "Authorization": f"Bearer {token}"
        }
        url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/roles"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                return {'status': 'success', 'roles': response.json()}
            else:
                logger.error(f"Error fetching roles from Keycloak: {response.text}")
                return {'status': 'error', 'message': "Error fetching roles from Keycloak"}
    except Exception as e:
        logger.error(f"Exception fetching roles from Keycloak: {e}")
        return {'status': 'error', 'message': "Exception occurred while fetching roles from Keycloak"}


async def get_role_by_name(role_name: str) -> dict:
    """
    Fetch a specific role by its name from Keycloak.
    :param role_name:
    :return: A dictionary containing the status and role details or an error message.
    """
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error obtaining admin token"}
        headers = {
            "Authorization": f"Bearer {token}"
        }
        url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/roles/{role_name}"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                return {'status': 'success', 'role': response.json()}
            else:
                logger.error(f"Error fetching role from Keycloak: {response.text}")
                return {'status': 'error', 'message': "Error fetching role from Keycloak"}
    except Exception as e:
        logger.error(f"Exception fetching roles from Keycloak: {e}")
        return {'status': 'error', 'message': "Exception occurred while fetching role from Keycloak"}


async def get_role_management_permissions(role_id: str) -> dict:
    """
    Fetch management permissions for a specific role by its ID from Keycloak.
    :param role_id: The ID of the role.
    :return: A dictionary containing the status and permissions or an error message.
    """
    try:
        token = await get_admin_token()
        if not token:
            return {'status': 'error', 'message': "Error obtaining admin token"}
        headers = {
            "Authorization": f"Bearer {token}"
        }
        url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/roles-by-id/{role_id}/management/permissions"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                return {'status': 'success', 'permissions': response.json()}
            else:
                logger.error(f"Error fetching management permissions from Keycloak: {response.text}")
                return {'status': 'error', 'message': "Error fetching management permissions from Keycloak"}
    except Exception as e:
        logger.error(f"Exception fetching management permissions from Keycloak: {e}")
        return {'status': 'error', 'message': "Exception occurred while fetching management permissions from Keycloak"}


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
        return True

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
                        pass
                    else:
                        logger.error(f"Failed to create role '{role['name']}'. Status: {response.status}, Response: {await response.text()}")
                        success = False
        except aiohttp.ClientError as e:
            logger.error(f"Connection error while creating role '{role['name']}': {e}")
            success = False

    return success
