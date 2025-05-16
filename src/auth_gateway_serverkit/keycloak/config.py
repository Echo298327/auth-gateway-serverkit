from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import ValidationError
from typing import Optional


class Settings(BaseSettings):
    SERVER_URL: str
    CLIENT_ID: str
    REALM: str
    SCOPE: str
    KEYCLOAK_FRONTEND_URL: str
    KC_BOOTSTRAP_ADMIN_USERNAME: str
    KC_BOOTSTRAP_ADMIN_PASSWORD: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    CLIENT_SECRET: Optional[str] = None


try:
    settings = Settings()
except ValidationError as e:
    print("Configuration error:", e)
    import sys
    sys.exit(1)
