"""Keycloak Cleanup API Module for the auth gateway serverkit."""
import aiohttp
from .config import settings
from ..logger import init_logger
from .client_api import get_resource_id

logger = init_logger("serverkit.keycloak.cleanup")


async def get_policy_id(policy_name, admin_token, client_uuid) -> str | None:
    """
    Retrieve the policy ID for a given policy name.
    :param policy_name:
    :param admin_token:
    :param client_uuid:
    :return: Policy ID if found, None otherwise
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/policy"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    policies = await response.json()
                    for policy in policies:
                        if policy['name'] == policy_name:
                            return policy['id']
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while retrieving policy ID for '{policy_name}': {e}")
    return None


async def get_permission_id(permission_name, admin_token, client_uuid) -> str | None:
    """
    Retrieve the permission ID for a given permission name.
    :param permission_name:
    :param admin_token:
    :param client_uuid:
    :return: Permission ID if found, None otherwise
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/permission"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    permissions = await response.json()
                    for permission in permissions:
                        if permission['name'] == permission_name:
                            return permission['id']
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while retrieving permission ID for '{permission_name}': {e}")
    return None


async def delete_resource(resource_name, admin_token, client_uuid) -> bool:
    """
    Delete a resource in Keycloak by name.
    :param resource_name:
    :param admin_token:
    :param client_uuid:
    :return: True if successful or not found, False on error
    """
    # First get the resource ID
    resource_id = await get_resource_id(resource_name, admin_token, client_uuid)
    if not resource_id:
        return True  # Resource doesn't exist, consider it successful
    
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/resource/{resource_id}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.delete(url, headers=headers) as response:
                return response.status in [204, 404]  # Success or not found
    except aiohttp.ClientError:
        return False


async def delete_policy(policy_name, admin_token, client_uuid) -> bool:
    """
    Delete a policy in Keycloak by name.
    :param policy_name:
    :param admin_token:
    :param client_uuid:
    :return: True if successful or not found, False on error
    """
    # First get the policy ID
    policy_id = await get_policy_id(policy_name, admin_token, client_uuid)
    if not policy_id:
        return True  # Policy doesn't exist, consider it successful
    
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/policy/{policy_id}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.delete(url, headers=headers) as response:
                return response.status in [204, 404]  # Success or not found
    except aiohttp.ClientError:
        return False


async def delete_permission(permission_name, admin_token, client_uuid) -> bool:
    """
    Delete a permission in Keycloak by name.
    :param permission_name:
    :param admin_token:
    :param client_uuid:
    :return: True if successful or not found, False on error
    """
    # First get the permission ID
    permission_id = await get_permission_id(permission_name, admin_token, client_uuid)
    if not permission_id:
        return True  # Permission doesn't exist, consider it successful
    
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/permission/{permission_id}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.delete(url, headers=headers) as response:
                return response.status in [204, 404]  # Success or not found
    except aiohttp.ClientError:
        return False


async def get_all_permissions(admin_token, client_uuid) -> list:
    """
    Get all existing permissions from Keycloak.
    :param admin_token: Admin token for authentication
    :param client_uuid: Client UUID
    :return: List of all permission names
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/permission"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    permissions = await response.json()
                    return [p['name'] for p in permissions]
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while getting all permissions: {e}")
    return []


async def get_all_policies(admin_token, client_uuid) -> list:
    """
    Get all existing policies from Keycloak.
    :param admin_token: Admin token for authentication
    :param client_uuid: Client UUID
    :return: List of all policy names
    """
    headers = {
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    }
    url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/clients/{client_uuid}/authz/resource-server/policy"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    policies = await response.json()
                    return [p['name'] for p in policies]
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while getting all policies: {e}")
    return []


async def get_all_resources(admin_token, client_uuid) -> list:
    """
    Get all existing resources from Keycloak.
    :param admin_token: Admin token for authentication
    :param client_uuid: Client UUID
    :return: List of all resource names
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
                    return [r['name'] for r in resources]
    except aiohttp.ClientError as e:
        logger.error(f"Connection error while getting all resources: {e}")
    return []


async def cleanup_authorization_config(config, admin_token, client_uuid) -> bool:
    """
    Clean up ALL authorization resources, policies, and permissions from Keycloak.
    The config parameter is not used for deletion - we delete everything that exists.
    :param config: Configuration dictionary (not used for deletion, only for logging)
    :param admin_token: Admin token for authentication
    :param client_uuid: Client UUID
    :return: True if cleanup successful, False otherwise
    """
    
    # Step 1: Get and delete ALL existing permissions (dependencies first)
    existing_permissions = await get_all_permissions(admin_token, client_uuid)
    if existing_permissions:
        logger.info(f"Deleting {len(existing_permissions)} existing permissions...")
        failed_permissions = []
        for permission_name in existing_permissions:
            success = await delete_permission(permission_name, admin_token, client_uuid)
            if not success:
                failed_permissions.append(permission_name)
        
        if failed_permissions:
            logger.error(f"Failed to delete permissions: {failed_permissions}")
            return False
        else:
            logger.info("All existing permissions deleted successfully")
    else:
        logger.info("No existing permissions to delete")

    # Step 2: Get and delete ALL existing policies
    existing_policies = await get_all_policies(admin_token, client_uuid)
    if existing_policies:
        logger.info(f"Deleting {len(existing_policies)} existing policies...")
        failed_policies = []
        for policy_name in existing_policies:
            success = await delete_policy(policy_name, admin_token, client_uuid)
            if not success:
                failed_policies.append(policy_name)
        
        if failed_policies:
            logger.error(f"Failed to delete policies: {failed_policies}")
            return False
        else:
            logger.info("All existing policies deleted successfully")
    else:
        logger.info("No existing policies to delete")

    # Step 3: Get and delete ALL existing resources
    existing_resources = await get_all_resources(admin_token, client_uuid)
    if existing_resources:
        logger.info(f"Deleting {len(existing_resources)} existing resources...")
        failed_resources = []
        for resource_name in existing_resources:
            success = await delete_resource(resource_name, admin_token, client_uuid)
            if not success:
                failed_resources.append(resource_name)
        
        if failed_resources:
            logger.error(f"Failed to delete resources: {failed_resources}")
            return False
        else:
            logger.info("All existing resources deleted successfully")
    else:
        logger.info("No existing resources to delete")

    logger.info("Complete cleanup finished successfully")
    return True
