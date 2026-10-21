import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from .services import utc_iso


class PasswordHasher:
    LEGACY_ITERATIONS = 260_000

    def __init__(self, iterations):
        self.iterations = iterations
        self._dummy_salt = secrets.token_bytes(16)
        self._dummy_hash = self._derive("not-a-real-password", self._dummy_salt)

    def _derive(self, password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, self.iterations)

    def hash(self, password):
        salt = secrets.token_bytes(16)
        digest = self._derive(password, salt)
        return salt.hex(), digest.hex()

    def verify(self, password, salt_hex, digest_hex):
        valid, _ = self.verify_and_upgrade(password, salt_hex, digest_hex)
        return valid

    def verify_and_upgrade(self, password, salt_hex, digest_hex):
        try:
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
        except (TypeError, ValueError):
            self._derive(password, self._dummy_salt)
            return False, None
        candidate = self._derive(password, salt)
        if hmac.compare_digest(candidate, expected):
            return True, None
        legacy_candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, self.LEGACY_ITERATIONS
        )
        if hmac.compare_digest(legacy_candidate, expected):
            return True, self.hash(password)
        return False, None

    def verify_unknown_user(self, password):
        candidate = self._derive(password, self._dummy_salt)
        hmac.compare_digest(candidate, self._dummy_hash)


class LoginRateLimiter:
    def __init__(self, database, max_attempts, lock_seconds):
        self.database = database
        self.max_attempts = max_attempts
        self.lock_seconds = lock_seconds
        self.window_seconds = lock_seconds

    def is_blocked(self, key, now=None):
        key_hash = self._hash_key(key)
        current = self._time(now)
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT window_started_at, locked_until FROM login_attempts WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
        if not row:
            return False
        if row["locked_until"] and row["locked_until"] > current:
            return True
        threshold = (
            datetime.fromisoformat(current.replace("Z", "+00:00"))
            - timedelta(seconds=self.window_seconds)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        if row["window_started_at"] < threshold:
            self.succeeded(key)
        elif row["locked_until"] and row["locked_until"] <= current:
            self.succeeded(key)
        return False

    def failed(self, key, now=None):
        key_hash = self._hash_key(key)
        current = self._time(now)
        window_start = datetime.fromisoformat(current.replace("Z", "+00:00"))
        lock_until = (
            window_start + timedelta(seconds=self.lock_seconds)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        cutoff = (
            window_start - timedelta(seconds=self.window_seconds)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        with self.database.transaction(immediate=not self.database.is_postgres) as connection:
            connection.execute(
                """DELETE FROM login_attempts
                   WHERE window_started_at < ? AND (locked_until IS NULL OR locked_until <= ?)""",
                (cutoff, current),
            )
            connection.execute(
                """INSERT INTO login_attempts
                   (key_hash, attempts, window_started_at, locked_until)
                   VALUES (?, 0, ?, NULL)
                   ON CONFLICT(key_hash) DO NOTHING""",
                (key_hash, current),
            )
            lock_clause = " FOR UPDATE" if self.database.is_postgres else ""
            row = connection.execute(
                "SELECT attempts, window_started_at, locked_until FROM login_attempts "
                "WHERE key_hash = ?" + lock_clause,
                (key_hash,),
            ).fetchone()
            if row["locked_until"] and row["locked_until"] > current:
                return
            attempts = row["attempts"]
            started = row["window_started_at"]
            if started < cutoff:
                attempts = 0
                started = current
            attempts += 1
            updated_lock = lock_until if attempts >= self.max_attempts else None
            connection.execute(
                """UPDATE login_attempts SET attempts = ?, window_started_at = ?,
                   locked_until = ? WHERE key_hash = ?""",
                (attempts, started, updated_lock, key_hash),
            )

    def succeeded(self, key):
        key_hash = self._hash_key(key)
        with self.database.transaction(immediate=not self.database.is_postgres) as connection:
            connection.execute("DELETE FROM login_attempts WHERE key_hash = ?", (key_hash,))

    @staticmethod
    def _hash_key(key):
        return hashlib.sha256("{}\0{}".format(*key).encode("utf-8")).hexdigest()

    @staticmethod
    def _time(now):
        value = datetime.fromtimestamp(now, timezone.utc) if now is not None else datetime.now(timezone.utc)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")


class SessionStore:
    def __init__(self, database, ttl_seconds, max_sessions):
        self.database = database
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions

    def create(self, user):
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        created_at = utc_iso()
        from datetime import datetime, timedelta, timezone
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        with self.database.transaction(immediate=not self.database.is_postgres) as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (created_at,))
            count = connection.execute(
                "SELECT COUNT(*) AS session_count FROM sessions"
            ).fetchone()["session_count"]
            excess = count - self.max_sessions + 1
            if excess > 0:
                if self.database.is_postgres:
                    connection.execute(
                        """DELETE FROM sessions WHERE token_hash IN
                           (SELECT token_hash FROM sessions ORDER BY created_at LIMIT ?)""",
                        (excess,),
                    )
                else:
                    connection.execute(
                        """DELETE FROM sessions WHERE token_hash IN
                           (SELECT token_hash FROM sessions ORDER BY created_at LIMIT ?)""",
                        (excess,),
                    )
            connection.execute(
                "INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, user["username"], created_at, expires_at),
            )
        return token

    def get(self, token):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self.database.connection() as connection:
            row = connection.execute(
                """SELECT users.username, users.role
                   FROM sessions JOIN users USING (username)
                   WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
                (token_hash, utc_iso()),
            ).fetchone()
            return dict(row) if row else None

    def revoke(self, token):
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self.database.transaction(immediate=not self.database.is_postgres) as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


class AuthenticationService:
    def __init__(self, repository, password_hasher, rate_limiter):
        self.repository = repository
        self.password_hasher = password_hasher
        self.rate_limiter = rate_limiter

    def authenticate(self, username, password, remote_address):
        key = (remote_address[:64], username[:80].casefold())
        if self.rate_limiter.is_blocked(key):
            return None
        user = self.repository.find_user(username[:80])
        if user:
            valid, upgraded_hash = self.password_hasher.verify_and_upgrade(
                password, user["salt"], user["password_hash"]
            )
        else:
            self.password_hasher.verify_unknown_user(password)
            valid = False
            upgraded_hash = None
        if not valid:
            self.rate_limiter.failed(key)
            return None
        if upgraded_hash:
            self.repository.update_password_hash(user["username"], *upgraded_hash)
        self.rate_limiter.succeeded(key)
        return {"username": user["username"], "role": user["role"]}
