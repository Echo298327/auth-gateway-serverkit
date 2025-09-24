from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import ValidationError
from typing import Optional


class Settings(BaseSettings):
    GOOGLE_APPLICATION_CREDENTIALS: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

try:
    settings = Settings()
except ValidationError as e:
    print("Configuration error:", e)
    import sys
    sys.exit(1)
