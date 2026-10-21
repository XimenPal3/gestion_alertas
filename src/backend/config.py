import os
from dataclasses import dataclass
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    database_path: Path = SOURCE_ROOT / "data" / "alerts.sqlite3"
    database_url: str = ""
    static_root: Path = SOURCE_ROOT
    host: str = "127.0.0.1"
    port: int = 8765
    session_seconds: int = 8 * 60 * 60
    password_iterations: int = 600_000
    body_limit: int = 16_384
    max_sessions: int = 512
    max_login_attempts: int = 5
    login_lock_seconds: int = 300
    cookie_secure: bool = False

    @classmethod
    def from_environment(cls):
        database_url = os.environ.get("DATABASE_URL", "").strip()
        if database_url.startswith("postgres://"):
            database_url = "postgresql://" + database_url[len("postgres://"):]
        return cls(
            database_path=Path(os.environ.get(
                "ALERTS_DB", str(SOURCE_ROOT / "data" / "alerts.sqlite3")
            )).expanduser().resolve(),
            database_url=database_url,
            host="127.0.0.1",
            port=int(os.environ.get("PORT", "8765")),
            cookie_secure=os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes"),
        )
