from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "Uni-Gap Security Backend"
    app_env: str = "development"
    secret_key: str = "uni-gap-demo-development-secret-change-me-32chars"
    access_token_expire_minutes: int = 480
    database_url: str = "sqlite:///./data/uni_gap.db"
    cors_origins: str = "http://localhost:3000"
    ml_service_url: str = "http://localhost:8001"
    role3_service_url: str = "http://localhost:8002"
    role3_service_enabled: bool = True
    ml_service_timeout_seconds: float = 15.0
    ml_service_enabled: bool = True
    demo_stream_enabled: bool = False
    demo_stream_interval_seconds: float = 4.0
    pcap_max_mb: int = 250
    upload_dir: str = "./storage/pcaps"
    report_dir: str = "./storage/reports"

    @property
    def cors_list(self):
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

@lru_cache
def get_settings():
    return Settings()
