from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    graylog_host: str = "http://graylog:9000"
    graylog_username: str = "admin"
    graylog_password: str = "admin"
    anthropic_api_key: str = ""
    cors_origins: list[str] = [
        "http://localhost:8080",
        "http://localhost:80",
        "http://frontend",
        "http://frontend:80",
    ]

    class Config:
        env_file = ".env"


settings = Settings()
