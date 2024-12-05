from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import ValidationError
from .schemas import AuthConfigurations
from typing import Optional


class Settings(BaseSettings):
    SERVER_URL: str
    REALM: str
    CLIENT_ID: str
    AUTHORIZATION_URL: str
    TOKEN_URL: str

    # class variables not defined in the .env file
    CLIENT_SECRET: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @classmethod
    def load_keycloak_credentials(cls) -> AuthConfigurations:
        return AuthConfigurations(
            server_url=cls.SERVER_URL,
            realm=cls.REALM,
            client_id=cls.CLIENT_ID,
            authorization_url=cls.AUTHORIZATION_URL,
            token_url=cls.TOKEN_URL,
            client_secret=None,
        )


try:
    settings = Settings()
except ValidationError as e:
    print("Configuration error:", e)
    import sys
    sys.exit(1)
