import logging
import sqlite3
from urllib.parse import urlparse
from http import HTTPStatus

from flask import Flask, jsonify, request, send_from_directory

try:
    import psycopg
except ImportError:
    psycopg = None

from .services import ROLES


MAX_USERNAME_LENGTH = 80
MAX_PASSWORD_LENGTH = 256


def create_app(application):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = application.settings.body_limit
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def validate_write_origin():
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        origin = request.headers.get("Origin")
        if not origin:
            return jsonify(error="Se requiere un origen permitido."), HTTPStatus.FORBIDDEN
        parsed = urlparse(origin)
        allowed_schemes = ("https",) if application.settings.cookie_secure else ("http",)
        local_host = parsed.hostname and parsed.hostname.lower() in ("127.0.0.1", "localhost")
        deployed_host = application.settings.cookie_secure
        if parsed.scheme not in allowed_schemes or parsed.netloc != request.host:
            return jsonify(error="Origen no permitido."), HTTPStatus.FORBIDDEN
        if not local_host and not deployed_host:
            return jsonify(error="Origen no permitido."), HTTPStatus.FORBIDDEN
        if application.settings.cookie_secure and parsed.scheme != "https":
            return jsonify(error="Se requiere HTTPS."), HTTPStatus.FORBIDDEN
        return None

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify(error="Tamaño de solicitud inválido."), HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    @app.errorhandler(sqlite3.Error)
    def sqlite_error(error):
        app.logger.exception("Database request failed: %s", error)
        return jsonify(error="No fue posible procesar la solicitud. Intente de nuevo."), HTTPStatus.INTERNAL_SERVER_ERROR

    if psycopg is not None:
        @app.errorhandler(psycopg.Error)
        def postgres_error(error):
            app.logger.exception("Database request failed: %s", error)
            return jsonify(error="No fue posible procesar la solicitud. Intente de nuevo."), HTTPStatus.INTERNAL_SERVER_ERROR

    @app.errorhandler(Exception)
    def unexpected_error(error):
        app.logger.exception("Unhandled request failure: %s", error)
        return jsonify(error="Error interno. Intente de nuevo."), HTTPStatus.INTERNAL_SERVER_ERROR

    def authenticated_user():
        return application.get_actor(request.cookies.get("session"))

    def json_body():
        if not request.is_json:
            return None, (jsonify(error="El Content-Type debe ser application/json."), HTTPStatus.BAD_REQUEST)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return None, (jsonify(error="El cuerpo debe ser un objeto JSON válido."), HTTPStatus.BAD_REQUEST)
        return data, None

    def require_user():
        user = authenticated_user()
        if not user:
            return None, (jsonify(error="Inicie sesión para continuar."), HTTPStatus.UNAUTHORIZED)
        return user, None

    @app.get("/")
    def index():
        return send_from_directory(application.settings.static_root, "index.html")

    @app.get("/app.js")
    def app_js():
        return send_from_directory(
            application.settings.static_root, "app.js",
            mimetype="text/javascript",
        )

    @app.get("/styles.css")
    def styles_css():
        return send_from_directory(
            application.settings.static_root, "styles.css",
            mimetype="text/css",
        )

    @app.get("/api/session")
    def session():
        return jsonify(user=authenticated_user(), roles=ROLES)

    @app.get("/api/health")
    def health():
        application.repository.health_check()
        return jsonify(status="ok")

    @app.post("/api/login")
    def login():
        data, error = json_body()
        if error:
            return error
        username = data.get("username")
        password = data.get("password")
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not username.strip()
            or len(username) > MAX_USERNAME_LENGTH
            or len(password) > MAX_PASSWORD_LENGTH
        ):
            return jsonify(error="Credenciales inválidas."), HTTPStatus.BAD_REQUEST
        user = application.authenticate(username.strip(), password, request.remote_addr or "unknown")
        if not user:
            return jsonify(
                error="Credenciales incorrectas o cuenta temporalmente bloqueada."
            ), HTTPStatus.UNAUTHORIZED
        token = application.create_session(user)
        response = jsonify(user=user)
        response.set_cookie(
            "session",
            token,
            max_age=application.settings.session_seconds,
            httponly=True,
            secure=application.settings.cookie_secure,
            samesite="Strict",
            path="/",
        )
        return response

    @app.post("/api/logout")
    def logout():
        user, error = require_user()
        if error:
            return error
        application.revoke_session(request.cookies.get("session"))
        response = jsonify(ok=True)
        response.delete_cookie(
            "session", path="/", httponly=True, secure=application.settings.cookie_secure,
            samesite="Strict",
        )
        return response

    @app.get("/api/dashboard")
    def dashboard():
        user, error = require_user()
        if error:
            return error
        return jsonify(application.alerts.dashboard())

    @app.get("/api/audit")
    def audit():
        user, error = require_user()
        if error:
            return error
        if user["role"] != "auditor":
            return jsonify(error="La vista de auditoría requiere el rol auditor."), HTTPStatus.FORBIDDEN
        return jsonify(application.alerts.audit())

    @app.get("/api/users")
    def users():
        user, error = require_user()
        if error:
            return error
        if user["role"] != "supervisor":
            return jsonify(error="Solo el supervisor puede consultar la lista de asignación."), HTTPStatus.FORBIDDEN
        return jsonify(users=application.repository.list_users(role="analyst"))

    @app.get("/api/alerts/<alert_id>")
    def alert_detail(alert_id):
        user, error = require_user()
        if error:
            return error
        if not alert_id.replace("-", "").isalnum() or len(alert_id) > 16:
            return jsonify(error="Identificador inválido."), HTTPStatus.BAD_REQUEST
        alert = application.alerts.detail(alert_id)
        if not alert:
            return jsonify(error="Alerta no encontrada."), HTTPStatus.NOT_FOUND
        return jsonify(alert)

    @app.post("/api/alerts/<alert_id>/actions")
    def alert_action(alert_id):
        user, error = require_user()
        if error:
            return error
        if not alert_id.replace("-", "").isalnum() or len(alert_id) > 16:
            return jsonify(error="Identificador inválido."), HTTPStatus.BAD_REQUEST
        data, error = json_body()
        if error:
            return error
        try:
            result = application.alerts.apply_action(alert_id, user, data)
        except LookupError as action_error:
            return jsonify(error=str(action_error)), HTTPStatus.NOT_FOUND
        except PermissionError as action_error:
            return jsonify(error=str(action_error)), HTTPStatus.FORBIDDEN
        except ValueError as action_error:
            return jsonify(error=str(action_error)), HTTPStatus.BAD_REQUEST
        return jsonify(result)

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="No encontrado."), HTTPStatus.NOT_FOUND
        return jsonify(error="No encontrado."), HTTPStatus.NOT_FOUND

    return app


def create_handler(application):
    return create_app(application)
