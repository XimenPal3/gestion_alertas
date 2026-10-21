import sys

from .config import Settings
from .database import Database
from .repository import AlertRepository
from .security import AuthenticationService, LoginRateLimiter, PasswordHasher, SessionStore
from .seed import seed_if_empty
from .services import AlertService


class Application:
    def __init__(self, settings=None, output=None):
        self.settings = settings or Settings.from_environment()
        output = output or (lambda message: print(message, flush=True))
        self.database = Database(self.settings.database_path, self.settings.database_url)
        self.database.initialize()
        self.repository = AlertRepository(self.database)
        self.password_hasher = PasswordHasher(self.settings.password_iterations)
        seed_if_empty(self.database, self.password_hasher, output=output)
        self.rate_limiter = LoginRateLimiter(
            self.database, self.settings.max_login_attempts, self.settings.login_lock_seconds
        )
        self.authentication = AuthenticationService(
            self.repository, self.password_hasher, self.rate_limiter
        )
        self.sessions = SessionStore(
            self.database, self.settings.session_seconds, self.settings.max_sessions
        )
        self.alerts = AlertService(self.database, self.repository)

    def authenticate(self, username, password, remote_address):
        return self.authentication.authenticate(username, password, remote_address)

    def create_session(self, user):
        return self.sessions.create(user)

    def get_actor(self, token):
        return self.sessions.get(token) if token else None

    def revoke_session(self, token):
        if token:
            self.sessions.revoke(token)


def create_application(settings=None, output=None):
    return Application(settings=settings, output=output)
