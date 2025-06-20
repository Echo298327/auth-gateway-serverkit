"""Keycloak roles API module for managing roles in Keycloak"""
import httpx
from config import settings
from ..logger import init_logger
from .client_api import get_admin_token

logger = init_logger("serverkit.keycloak.roles")


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
