import sqlite3
from contextlib import contextmanager


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('supervisor','analyst','reviewer','auditor')),
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    summary TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('critical','high','medium','low')),
    status TEXT NOT NULL CHECK (status IN ('new','assigned','analysis','escalated','closed','reopened')),
    assigned_to TEXT,
    created_at TEXT NOT NULL,
    due_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exceptions (
    code TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    title TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status_due ON alerts(status, due_at);
CREATE INDEX IF NOT EXISTS idx_events_alert_id_id ON events(alert_id, id);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS login_attempts (
    key_hash TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    window_started_at TEXT NOT NULL,
    locked_until TEXT
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_locked_until ON login_attempts(locked_until);
"""

POSTGRES_SCHEMA = SQLITE_SCHEMA.replace(
    "id INTEGER PRIMARY KEY AUTOINCREMENT", "id BIGSERIAL PRIMARY KEY"
)


class PostgresConnection:
    def __init__(self, connection):
        self.raw = connection

    def execute(self, sql, parameters=()):
        return self.raw.execute(sql.replace("?", "%s"), parameters)

    def executemany(self, sql, parameters):
        return self.raw.executemany(sql.replace("?", "%s"), parameters)

    @property
    def in_transaction(self):
        return self.raw.info.transaction_status.name != "IDLE"

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()

    def __enter__(self):
        self.raw.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self.raw.__exit__(exc_type, exc_value, traceback)


class Database:
    def __init__(self, path, database_url=""):
        self.path = path
        self.database_url = database_url
        self.is_postgres = bool(database_url)

    def connect(self):
        if self.is_postgres:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as error:
                raise RuntimeError(
                    "PostgreSQL requiere las dependencias de requirements.txt."
                ) from error
            return PostgresConnection(psycopg.connect(
                self.database_url, row_factory=dict_row, connect_timeout=10, autocommit=True
            ))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def connection(self):
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self, immediate=False):
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self):
        if self.is_postgres:
            with self.transaction() as connection:
                statements = [statement.strip() for statement in POSTGRES_SCHEMA.split(";") if statement.strip()]
                for statement in statements:
                    connection.execute(statement)
        else:
            with self.connection() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(SQLITE_SCHEMA)
