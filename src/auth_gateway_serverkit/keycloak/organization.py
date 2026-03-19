"""Keycloak Organization Module for the auth gateway serverkit."""
import httpx
from ..logger import init_logger
from .config import settings
from .client import get_admin_token

logger = init_logger(__name__)

_BASE_URL = None


def _get_base_url():
    global _BASE_URL
    if not _BASE_URL:
        _BASE_URL = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}/organizations"
    return _BASE_URL


async def _get_headers():
    token = await get_admin_token()
    if not token:
        logger.error("Failed to obtain admin token for organization operation")
        return None
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }


async def create_organization(name: str, description: str = None, domains: list = None) -> dict | None:
    """Create an organization in Keycloak."""
    headers = await _get_headers()
    if not headers:
        return None
    body = {"name": name, "enabled": True}
    if description:
        body["description"] = description
    if domains:
        body["domains"] = [{"name": d, "verified": True} for d in domains]
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(_get_base_url(), json=body, headers=headers)
            if response.status_code == 201:
                location = response.headers.get("Location", "")
                org_id = location.rstrip("/").split("/")[-1]
                logger.info(f"Organization '{name}' created in Keycloak: {org_id}")
                return {"id": org_id, "name": name}
            logger.error(f"Failed to create organization: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logger.error(f"Error creating organization: {e}")
        return None


async def get_organization(org_id: str) -> dict | None:
    """Get an organization by ID from Keycloak."""
    headers = await _get_headers()
    if not headers:
        return None
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(f"{_get_base_url()}/{org_id}", headers=headers)
            if response.status_code == 200:
                return response.json()
            return None
    except Exception as e:
        logger.error(f"Error getting organization: {e}")
        return None


async def list_organizations(first: int = 0, max_results: int = 100) -> list:
    """List all organizations in Keycloak."""
    headers = await _get_headers()
    if not headers:
        return []
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(
                _get_base_url(),
                headers=headers,
                params={"first": first, "max": max_results},
            )
            if response.status_code == 200:
                return response.json()
            return []
    except Exception as e:
        logger.error(f"Error listing organizations: {e}")
        return []


async def update_organization(org_id: str, data: dict) -> bool:
    """Update an organization in Keycloak."""
    headers = await _get_headers()
    if not headers:
        return False
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.put(f"{_get_base_url()}/{org_id}", json=data, headers=headers)
            if response.status_code == 204:
                logger.info(f"Organization {org_id} updated in Keycloak")
                return True
            logger.error(f"Failed to update organization: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error updating organization: {e}")
        return False


async def delete_organization(org_id: str) -> bool:
    """Delete an organization from Keycloak."""
    headers = await _get_headers()
    if not headers:
        return False
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.delete(f"{_get_base_url()}/{org_id}", headers=headers)
            if response.status_code == 204:
                logger.info(f"Organization {org_id} deleted from Keycloak")
                return True
            logger.error(f"Failed to delete organization: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error deleting organization: {e}")
        return False


async def add_member_to_organization(org_id: str, user_id: str) -> bool:
    """Add a user as a member of an organization in Keycloak."""
    headers = await _get_headers()
    if not headers:
        return False
    try:
        url = f"{_get_base_url()}/{org_id}/members"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(url, json=user_id, headers=headers)
            if response.status_code in (201, 204):
                logger.info(f"User {user_id} added to organization {org_id}")
                return True
            logger.error(f"Failed to add member: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error adding member to organization: {e}")
        return False


async def remove_member_from_organization(org_id: str, user_id: str) -> bool:
    """Remove a user from an organization in Keycloak."""
    headers = await _get_headers()
    if not headers:
        return False
    try:
        url = f"{_get_base_url()}/{org_id}/members/{user_id}"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.delete(url, headers=headers)
            if response.status_code == 204:
                logger.info(f"User {user_id} removed from organization {org_id}")
                return True
            logger.error(f"Failed to remove member: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error removing member from organization: {e}")
        return False


async def get_organization_members(org_id: str, first: int = 0, max_results: int = 100) -> list:
    """Get all members of an organization from Keycloak."""
    headers = await _get_headers()
    if not headers:
        return []
    try:
        url = f"{_get_base_url()}/{org_id}/members"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers, params={"first": first, "max": max_results})
            if response.status_code == 200:
                return response.json()
            return []
    except Exception as e:
        logger.error(f"Error getting organization members: {e}")
        return []


async def get_user_organizations(user_id: str) -> list:
    """Get all organizations a user belongs to."""
    headers = await _get_headers()
    if not headers:
        return []
    try:
        url = f"{_get_base_url()}/members/{user_id}/organizations"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            return []
    except Exception as e:
        logger.error(f"Error getting user organizations: {e}")
        return []


async def assign_organization_scope_to_client(admin_token: str) -> bool:
    """
    Assign the 'organization' client-scope as a default scope to the client.
    This ensures organization information is included in tokens.
    """
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}
    base = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(f"{base}/client-scopes", headers=headers)
            if resp.status_code != 200:
                logger.error(f"Failed to get client-scopes: {resp.status_code}")
                return False
            scopes = resp.json()
            org_scope = next((s for s in scopes if s.get("name") == "organization"), None)
            if not org_scope:
                logger.warning("Organization client-scope not found — may not be created by Keycloak yet")
                return True
            scope_id = org_scope["id"]
            logger.info(f"Found organization client-scope: {scope_id}")

            clients_resp = await client.get(f"{base}/clients?clientId={settings.CLIENT_ID}", headers=headers)
            if clients_resp.status_code != 200 or not clients_resp.json():
                logger.error(f"Client '{settings.CLIENT_ID}' not found")
                return False
            client_uuid = clients_resp.json()[0]["id"]

            await client.delete(f"{base}/clients/{client_uuid}/optional-client-scopes/{scope_id}", headers=headers)

            resp = await client.put(f"{base}/clients/{client_uuid}/default-client-scopes/{scope_id}", headers=headers)
            if resp.status_code in (204, 409):
                logger.info(f"Organization client-scope assigned to client '{settings.CLIENT_ID}' as default")
                return True
            logger.warning(f"Failed to assign organization scope: {resp.status_code}")
            return True
    except Exception as e:
        logger.error(f"Error assigning organization scope: {e}")
        return False


async def configure_organization_attributes(admin_token: str) -> bool:
    """
    Configure the organization client-scope mapper to include org attributes in tokens.
    """
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}
    base = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(f"{base}/client-scopes", headers=headers)
            if resp.status_code != 200:
                logger.error(f"Failed to get client-scopes: {resp.status_code}")
                return False
            scopes = resp.json()
            org_scope = next((s for s in scopes if s.get("name") == "organization"), None)
            if not org_scope:
                logger.warning("Organization client-scope not found")
                return True
            scope_id = org_scope["id"]

            mappers_resp = await client.get(f"{base}/client-scopes/{scope_id}/protocol-mappers/models", headers=headers)
            if mappers_resp.status_code != 200:
                logger.error(f"Failed to get mappers: {mappers_resp.status_code}")
                return False
            mappers = mappers_resp.json()
            org_mapper = next((m for m in mappers if m.get("protocolMapper") == "oidc-organization-membership-mapper"), None)
            if not org_mapper:
                logger.warning("Organization membership mapper not found")
                return True
            mapper_id = org_mapper["id"]

            updated_mapper = {
                "id": mapper_id,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-organization-membership-mapper",
                "name": org_mapper.get("name", "organization"),
                "consentRequired": False,
                "config": {
                    "id.token.claim": "true",
                    "introspection.token.claim": "true",
                    "access.token.claim": "true",
                    "claim.name": "organization",
                    "jsonType.label": "String",
                    "multivalued": "true",
                    "lightweight.claim": "false",
                    "userinfo.token.claim": "false",
                    "addOrganizationAttributes": "true",
                    "addOrganizationId": "false",
                },
            }
            resp = await client.put(
                f"{base}/client-scopes/{scope_id}/protocol-mappers/models/{mapper_id}",
                json=updated_mapper,
                headers=headers,
            )
            if resp.status_code == 204:
                logger.info("Organization attributes enabled in mapper configuration")
                return True
            logger.error(f"Failed to update mapper: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        logger.error(f"Error configuring organization attributes: {e}")
        return False
