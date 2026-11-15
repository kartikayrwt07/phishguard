"""
Core application configuration management using Pydantic Settings v2.
"""
from typing import List, Union
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "PhishGuard"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "insecure-secret-key-change-for-production-min-32-chars"
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./phishguard_dev.db"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # Redis Cache
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_SECONDS: int = 3600

    # Security & Tokens
    JWT_SECRET: str = "insecure-jwt-secret-change-for-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Threat Intelligence
    URLHAUS_API_ENABLED: bool = True
    URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1/"
    URLHAUS_TIMEOUT_SECONDS: float = 2.0

    PHISHTANK_API_ENABLED: bool = False
    PHISHTANK_API_KEY: str = ""
    PHISHTANK_TIMEOUT_SECONDS: float = 2.0

    GOOGLE_SAFE_BROWSING_ENABLED: bool = False
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_TIMEOUT_SECONDS: float = 2.0

    # Scoring Thresholds
    MIN_PHISHING_THRESHOLD: float = 70.0
    MIN_SUSPICIOUS_THRESHOLD: float = 30.0

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


settings = Settings()

