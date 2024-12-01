from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseSettings):
    SERVER_URL: str = os.getenv("SERVER_URL")
    CLIENT_ID: str = os.getenv("CLIENT_ID")
    REALM: str = os.getenv("REALM")
    SCOPE: str = os.getenv("SCOPE")
    KEYCLOAK_USER: str = os.getenv("KEYCLOAK_USER")
    KEYCLOAK_PASSWORD: str = os.getenv("KEYCLOAK_PASSWORD")


settings = Settings()
