from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    lab_mode: bool = True
    max_prefix: int = 24
    NVD_API_KEY: str | None = None
    OLLAMA_URL: str = 'http://localhost:11434'
    OLLAMA_MODEL: str = 'llama3.2:3b'


settings = Settings()