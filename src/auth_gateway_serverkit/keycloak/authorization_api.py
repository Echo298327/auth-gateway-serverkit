import aiohttp
from typing import Dict, Optional
from .config import settings
from .client_api import get_admin_token, get_client_uuid
from ..logger import init_logger
from .json_transformer import KeycloakConfigTransformer


logger = init_logger("serverkit.keycloak.authorization")


class KeycloakAuthorizationAPI:

    def __init__(self):
        self.base_url = f"{settings.SERVER_URL}/admin/realms/{settings.REALM}"

    async def update_authorization_config(self, authorization_config: Dict) -> bool:
        """Update complete authorization configuration via API"""

        try:
            # Get admin token and client UUID
            admin_token = await get_admin_token()
            if not admin_token:
                logger.error("Failed to get admin token")
                return False

            client_uuid = await get_client_uuid(admin_token)
            if not client_uuid:
                logger.error("Failed to get client UUID")
                return False

            # Update authorization settings
            url = f"{self.base_url}/clients/{client_uuid}/authz/resource-server"
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }

            async with aiohttp.ClientSession() as session:
                async with session.put(url, json=authorization_config, headers=headers) as response:
                    if response.status == 200:
                        logger.info("Authorization configuration updated successfully")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Failed to update authorization config: {error_text}")
                        return False

        except Exception as e:
            logger.error(f"Error updating authorization configuration: {e}")
            return False

    async def sync_configuration(self, config_file_path: str) -> bool:
        """Load, transform, and sync configuration"""

        try:
            # Transform configuration
            transformer = KeycloakConfigTransformer()
            keycloak_config = transformer.load_and_transform(config_file_path)

            # Update via API
            return await self.update_authorization_config(keycloak_config)

        except Exception as e:
            logger.error(f"Error syncing configuration: {e}")
            return False

    async def get_current_authorization_config(self) -> Optional[Dict]:
        """Get current authorization configuration"""

        try:
            admin_token = await get_admin_token()
            client_uuid = await get_client_uuid(admin_token)

            url = f"{self.base_url}/clients/{client_uuid}/authz/resource-server"
            headers = {'Authorization': f'Bearer {admin_token}'}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logger.error(f"Failed to get current config: {response.status}")
                        return None

        except Exception as e:
            logger.error(f"Error getting current configuration: {e}")
            return None
