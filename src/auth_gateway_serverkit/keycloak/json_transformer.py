import json
from typing import Dict


class KeycloakConfigTransformer:

    def transform_config(self, simple_config: Dict) -> Dict:
        """Transform simple config to Keycloak authorization format"""

        keycloak_config = {
            "allowRemoteResourceManagement": True,
            "policyEnforcementMode": "ENFORCING",
            "resources": [],
            "policies": [],
            "permissions": [],
            "scopes": []
        }

        # Transform resources
        for resource in simple_config.get("resources", []):
            keycloak_config["resources"].append({
                "name": resource["name"],
                "displayName": resource["displayName"],
                "uris": [resource["url"]],
                "type": "urn:resource-server:resource",
                "scopes": []
            })

        # Transform policies
        for policy in simple_config.get("policies", []):
            keycloak_config["policies"].append({
                "name": policy["name"],
                "description": policy["description"],
                "type": "role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {
                    "roles": json.dumps([
                        {"id": role, "required": False}
                        for role in policy["roles"]
                    ])
                }
            })

        # Transform permissions
        for permission in simple_config.get("permissions", []):
            keycloak_config["permissions"].append({
                "name": permission["name"],
                "description": permission["description"],
                "type": "resource",
                "logicType": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {
                    "resources": json.dumps(permission["resources"]),
                    "policies": json.dumps(permission["policies"])
                }
            })

        return keycloak_config

    def load_and_transform(self, config_file_path: str) -> Dict:
        """Load simple config and transform to Keycloak format"""
        with open(config_file_path, 'r') as f:
            simple_config = json.load(f)
        return self.transform_config(simple_config)
