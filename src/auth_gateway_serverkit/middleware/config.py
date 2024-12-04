from pydantic_settings import BaseSettings
from .schemas import AuthConfigurations
import os


class Settings(BaseSettings):
    SERVER_URL: str = os.getenv("SERVER_URL")
    REALM: str = os.getenv("REALM")
    CLIENT_ID: str = os.getenv("CLIENT_ID")
    CLIENT_SECRET: str = os.getenv("CLIENT_SECRET")
    AUTHORIZATION_URL: str = os.getenv("AUTHORIZATION_URL")
    TOKEN_URL: str = os.getenv("TOKEN_URL")

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


settings = Settings()

