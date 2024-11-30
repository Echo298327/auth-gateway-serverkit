from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseSettings):
    SERVER_URL: str = os.getenv("SERVER_URL")
    REALM: str = os.getenv("REALM")
    CLIENT_ID: str = os.getenv("CLIENT_ID")
    KEYCLOAK_USER = os.getenv("KEYCLOAK_USER")
    KEYCLOAK_PASSWORD = os.getenv("KEYCLOAK_PASSWORD")


settings = Settings()
