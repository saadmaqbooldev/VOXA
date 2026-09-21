from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="VOXA_", extra="ignore")

    data_dir: Path = Path("./data")
    models_dir: Path = Path("./models")
    db_path: Path = Path("./voxa_scans.db")
    log_dir: Path = Path("./logs")
    log_level: str = "INFO"

    max_file_size_mb: int = 100
    extraction_timeout_seconds: int = 10


settings = Settings()
