import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("ALERTS_DB", ROOT / "data" / "alerts.sqlite3"))
HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8765"))
SESSION_HOURS = 8
PBKDF2_ROUNDS = 260_000
BODY_LIMIT = 16_384
STATUS_LABELS = {
    "new": "Nueva",
    "assigned": "Asignada",
    "analysis": "En análisis",
    "escalated": "Escalada",
    "closed": "Cerrada",
    "reopened": "Reabierta",
}
PRIORITY_LABELS = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
ROLES = {
    "supervisor": "Supervisor",
    "analyst": "Analista",
    "reviewer": "Revisor",
    "auditor": "Auditoría",
}
DEMO_USERS = [
    ("supervisor.d", "supervisor"),
    ("analista.a", "analyst"),
    ("analista.b", "analyst"),
    ("revisor.e", "reviewer"),
    ("auditoria.p", "auditor"),
]
LOGIN_FAILURES = {}
LOGIN_LOCK = threading.Lock()
SESSIONS = {}
SESSION_LOCK = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt.hex(), digest.hex()


def verify_password(password, salt, digest):
    _, candidate = password_hash(password, bytes.fromhex(salt))
    return hmac.compare_digest(candidate, digest)


def add_event(conn, alert_id, actor, event_type, from_status, to_status, reason, evidence):
    conn.execute(
        """INSERT INTO events
           (alert_id, actor, event_type, from_status, to_status, reason, evidence, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (alert_id, actor, event_type, from_status, to_status, reason, evidence, iso(utc_now())),
    )


def seed_alerts(conn):
    now = utc_now()
    examples = [
        ("AL-0192", "Movimientos inusuales en cuenta ficticia", "critical", "escalated", "analista.a", 0.25),
        ("AL-0188", "Transferencias en ráfaga", "high", "analysis", "analista.b", 1),
        ("AL-0181", "Cambio de datos de contacto", "medium", "assigned", "analista.a", 2),
        ("AL-0175", "Pagos fraccionados repetidos", "high", "analysis", "analista.c", 8),
        ("AL-0169", "Consulta de saldos atípica", "low", "new", None, 0.125),
        ("AL-0163", "Patrón de retiros sintético", "high", "closed", "analista.b", 5),
        ("AL-0157", "Reasignación de caso sin motivo", "medium", "assigned", "analista.c", 4),
        ("AL-0152", "Transferencia fuera de horario", "medium", "reopened", "analista.a", 2),
        ("AL-0149", "Múltiples intentos de acceso", "high", "escalated", "analista.b", 2),
        ("AL-0142", "Actividad inusual de tarjeta", "critical", "new", None, 0.1),
        ("AL-0138", "Depósitos repetidos de bajo monto", "medium", "analysis", "analista.c", 2),
        ("AL-0131", "Beneficiario nuevo recurrente", "low", "closed", "analista.a", 6),
        ("AL-0128", "Variación de perfil transaccional", "high", "assigned", "analista.b", 1),
        ("AL-0124", "Transferencia internacional ficticia", "critical", "analysis", "analista.c", 0.75),
        ("AL-0119", "Actividad nocturna atípica", "medium", "new", None, 0.25),
        ("AL-0112", "Dispersión de pagos simulada", "high", "analysis", "analista.a", 3),
        ("AL-0109", "Monto de operación inusual", "low", "closed", "analista.c", 1),
        ("AL-0102", "Cambio de canal frecuente", "medium", "closed", "analista.b", 7),
        ("AL-0098", "Cuenta sintética relacionada", "high", "escalated", "analista.a", 2),
        ("AL-0094", "Transferencias repetitivas", "medium", "analysis", "analista.b", 2),
        ("AL-0089", "Dispositivo no habitual", "low", "new", None, 2),
        ("AL-0083", "Depósito con patrón atípico", "high", "assigned", "analista.a", 1),
        ("AL-0078", "Retiros secuenciales simulados", "medium", "analysis", "analista.c", 2),
        ("AL-0071", "Consulta de cuenta sintética", "low", "new", None, 0.5),
    ]
    # Plazos académicos editables: 12 h, 5 d, 3 d y 7 d por prioridad.
    sla_hours = {"critical": 12, "high": 120, "medium": 72, "low": 168}
    for alert_id, summary, priority, status, assigned, age_days in examples:
        created = now - timedelta(days=age_days)
        due = created + timedelta(hours=sla_hours[priority])
        conn.execute(
            """INSERT INTO alerts
               (id, summary, priority, status, assigned_to, created_at, due_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (alert_id, summary, priority, status, assigned, iso(created), iso(due)),
        )
        add_event(conn, alert_id, "sistema", "created", None, "new",
                  "Alerta sintética generada por regla de demostración", "—")
        if status != "new":
            add_event(conn, alert_id, "supervisor.d", "assigned", "new", "assigned",
                      "Asignación de demostración por rol y carga de trabajo", "EV-DEMO-01")
        if status in ("analysis", "escalated", "closed", "reopened"):
            add_event(conn, alert_id, assigned or "analista.a", "started", "assigned", "analysis",
                      "Inicio de análisis sintético", "EV-DEMO-02")
        if status == "escalated":
            add_event(conn, alert_id, assigned or "analista.a", "escalated", "analysis", "escalated",
                      "Requiere segundo revisor por prioridad", "EV-DEMO-03")
        if status == "closed":
            add_event(conn, alert_id, assigned or "analista.a", "closed", "analysis", "closed",
                      "Cierre con justificación de demostración", "EV-DEMO-04")
        if status == "reopened":
            add_event(conn, alert_id, "supervisor.d", "reopened", "closed", "reopened",
                      "Reapertura sintética para revisión", "EV-DEMO-05")

    add_event(conn, "AL-0192", "analista.a", "blocked", "escalated", "escalated",
              "Intento de cerrar un caso crítico propio bloqueado por segregación",
              "Regla: segundo revisor distinto")
    conn.executemany(
        """INSERT INTO exceptions (code, alert_id, title, detail) VALUES (?, ?, ?, ?)""",
        [
            ("EXC-01", "AL-0163", "Cierre con justificación incompleta",
             "Excepción sintética importada para revisión de auditoría."),
            ("EXC-02", "AL-0157", "Reasignación sin motivo registrado",
             "Excepción sintética importada para revisión de auditoría."),
        ],
    )


def initialize():
    conn = database()
    try:
        conn.executescript(
            """
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
            """
        )
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            print("\nCuentas sintéticas de demostración (guarde estas contraseñas):", flush=True)
            for username, role in DEMO_USERS:
                password = secrets.token_urlsafe(15)
                salt, digest = password_hash(password)
                conn.execute(
                    "INSERT INTO users (username, role, salt, password_hash) VALUES (?, ?, ?, ?)",
                    (username, role, salt, digest),
                )
                print("  {}: {}".format(username, password), flush=True)
            print("Si necesita restablecerlas, detenga el servidor y elimine data/alerts.sqlite3.\n", flush=True)
        if conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0:
            seed_alerts(conn)
        conn.commit()
    finally:
        conn.close()


def get_user(username):
    conn = database()
    try:
        row = conn.execute("SELECT username, role FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def authenticate(username, password):
    now = time.time()
    key = username[:80]
    with LOGIN_LOCK:
        attempts, locked_until = LOGIN_FAILURES.get(key, (0, 0))
        if locked_until > now:
            return None
    conn = database()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (key,)).fetchone()
    finally:
        conn.close()
    if row and verify_password(password, row["salt"], row["password_hash"]):
        with LOGIN_LOCK:
            LOGIN_FAILURES.pop(key, None)
        return {"username": row["username"], "role": row["role"]}
    with LOGIN_LOCK:
        attempts += 1
        LOGIN_FAILURES[key] = (0, now + 300) if attempts >= 5 else (attempts, 0)
    return None


def dashboard_data():
    conn = database()
    try:
        rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
        alerts = [dict(row) for row in rows]
        counts = {status: 0 for status in STATUS_LABELS}
        for alert in alerts:
            counts[alert["status"]] += 1
        open_alerts = [alert for alert in alerts if alert["status"] != "closed"]
        now = utc_now()
        buckets = {"0-1": 0, "2-3": 0, "4-7": 0, ">7": 0}
        overdue = 0
        for alert in open_alerts:
            age = (now - datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00"))).total_seconds() / 86400
            buckets["0-1" if age < 2 else "2-3" if age < 4 else "4-7" if age <= 7 else ">7"] += 1
            if alert["due_at"] < iso(now):
                overdue += 1
        exceptions = [dict(row) for row in conn.execute(
            "SELECT * FROM exceptions ORDER BY code"
        ).fetchall()]
        return {
            "alerts": alerts,
            "counts": counts,
            "open": len(open_alerts),
            "overdue": overdue,
            "reopened": counts["reopened"],
            "exception_count": len(exceptions),
            "age_buckets": buckets,
        }
    finally:
        conn.close()


def audit_data():
    conn = database()
    try:
        exceptions = [dict(row) for row in conn.execute(
            "SELECT * FROM exceptions ORDER BY code"
        ).fetchall()]
        now = iso(utc_now())
        overdue = [dict(row) for row in conn.execute(
            """SELECT * FROM alerts
               WHERE status != 'closed' AND due_at < ?
               ORDER BY due_at ASC""", (now,)
        ).fetchall()]
        return {"exceptions": exceptions, "overdue": overdue}
    finally:
        conn.close()


def alert_detail(alert_id):
    conn = database()
    try:
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not alert:
            return None
        result = dict(alert)
        result["events"] = [dict(row) for row in conn.execute(
            "SELECT * FROM events WHERE alert_id = ? ORDER BY id", (alert_id,)
        ).fetchall()]
        return result
    finally:
        conn.close()


def apply_action(alert_id, actor, action, payload):
    reason = payload.get("reason", "").strip()
    evidence = payload.get("evidence", "").strip()
    if not reason or len(reason) > 500:
        raise ValueError("El motivo es obligatorio (máximo 500 caracteres).")
    if not evidence or len(evidence) > 200:
        raise ValueError("Registre un identificador sintético de evidencia (máximo 200 caracteres).")

    conn = database()
    try:
        conn.execute("BEGIN IMMEDIATE")
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not alert:
            raise LookupError("No existe esa alerta.")
        status, priority = alert["status"], alert["priority"]
        username, role = actor["username"], actor["role"]
        assigned_to = alert["assigned_to"]
        target_user = payload.get("assignee", "").strip()
        transitions = {
            "assign": ("new", "reopened", "assigned"),
            "reassign": (None, None, None),
            "start": ("assigned", "reopened", "analysis"),
            "escalate": ("analysis", None, "escalated"),
            "close": ("analysis", None, "closed"),
            "approve_close": ("escalated", None, "closed"),
            "return": ("escalated", None, "analysis"),
            "reopen": ("closed", None, "reopened"),
        }
        if action not in transitions:
            raise ValueError("Acción no reconocida.")
        expected_status, _, next_status = transitions[action]
        if action == "reassign":
            if status not in ("assigned", "analysis", "escalated", "reopened"):
                raise ValueError("Solo puede reasignarse una alerta abierta.")
            next_status = status
        if action == "close" and priority == "critical":
            if status not in ("analysis", "escalated"):
                raise ValueError("El cierre crítico solo puede intentarse durante el análisis o la escalada.")
            if role != "analyst" or username != assigned_to:
                raise PermissionError("Solo el analista asignado puede intentar cerrar esta alerta.")
            record_blocked_in_transaction(conn, alert, username,
                "Cierre crítico bloqueado: requiere aprobación de un revisor distinto.")
            conn.commit()
            raise PermissionError("Cierre bloqueado: el caso crítico requiere un segundo revisor.")
        if action in ("assign", "start") and status not in transitions[action][:2]:
            raise ValueError("La alerta no está en un estado válido para esta acción.")
        if action not in ("assign", "reassign", "start") and status != expected_status:
            raise ValueError("La alerta cambió de estado. Actualice el tablero e intente de nuevo.")

        if action in ("assign", "reassign"):
            if role != "supervisor":
                raise PermissionError("Solo el supervisor puede asignar o reasignar alertas.")
            conn_user = conn.execute(
                "SELECT role FROM users WHERE username = ?", (target_user,)
            ).fetchone()
            if not conn_user or conn_user["role"] != "analyst":
                raise ValueError("Seleccione una cuenta activa con rol de analista.")
            if priority == "critical" and username == target_user:
                raise PermissionError("No puede asignarse y aprobar el mismo caso crítico.")
            assigned_to = target_user
        elif action == "start":
            if role != "analyst" or username != assigned_to:
                raise PermissionError("Solo el analista asignado puede iniciar el análisis.")
        elif action == "escalate":
            if role != "analyst" or username != assigned_to or priority != "critical":
                raise PermissionError("Solo el analista asignado puede escalar una alerta crítica.")
        elif action == "close":
            if role != "analyst" or username != assigned_to:
                raise PermissionError("Solo el analista asignado puede cerrar esta alerta.")
        elif action in ("approve_close", "return"):
            if username == assigned_to:
                record_blocked_in_transaction(conn, alert, username,
                    "Revisión propia bloqueada: el revisor es el analista asignado.")
                conn.commit()
                raise PermissionError("Segregación de funciones: el revisor debe ser distinto del analista.")
            if role != "reviewer":
                raise PermissionError("Solo un revisor puede decidir una alerta escalada.")
            if action == "approve_close" and priority != "critical":
                raise ValueError("La aprobación de segundo revisor es solo para alertas críticas.")
        elif action == "reopen":
            if role != "supervisor":
                raise PermissionError("Solo el supervisor puede reabrir alertas.")

        if action in ("assign", "reassign"):
            event_type = "assigned" if action == "assign" else "reassigned"
        else:
            event_type = action
        conn.execute(
            "UPDATE alerts SET status = ?, assigned_to = ? WHERE id = ?",
            (next_status, assigned_to, alert_id),
        )
        add_event(conn, alert_id, username, event_type, status, next_status, reason, evidence)
        conn.commit()
        return alert_detail(alert_id)
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


def record_blocked_in_transaction(conn, alert, actor, reason):
    add_event(conn, alert["id"], actor, "blocked", alert["status"], alert["status"],
              reason, "Control del sistema")


class Handler(BaseHTTPRequestHandler):
    server_version = "AlertasDemo/1.0"
    sys_version = ""

    def log_message(self, _format, *args):
        print("{} - {}".format(self.address_string(), _format % args), flush=True)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                         "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        super().end_headers()

    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Solicitud inválida.")
        if length < 1 or length > BODY_LIMIT:
            raise ValueError("Tamaño de solicitud inválido.")
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("El cuerpo debe ser JSON válido.")
        if not isinstance(data, dict):
            raise ValueError("El cuerpo debe ser un objeto JSON.")
        return data

    def get_actor(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["session"].value
        except (KeyError, CookieError):
            return None
        with SESSION_LOCK:
            session = SESSIONS.get(token)
            if not session or session["expires"] < time.time():
                SESSIONS.pop(token, None)
                return None
            return session["user"]

    def check_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        host = self.headers.get("Host", "")
        return parsed.scheme in ("http", "https") and parsed.netloc == host and host.split(":")[0] in ("127.0.0.1", "localhost")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.serve_file("index.html", "text/html; charset=utf-8")
            return
        if path in ("/app.js", "/styles.css"):
            content_type = "text/javascript; charset=utf-8" if path.endswith(".js") else "text/css; charset=utf-8"
            self.serve_file(path.lstrip("/"), content_type)
            return
        if not path.startswith("/api/"):
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "No encontrado."})
            return
        actor = self.get_actor()
        if path == "/api/session":
            self.send_json(HTTPStatus.OK, {"user": actor, "roles": ROLES})
            return
        if not actor:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Inicie sesión para continuar."})
            return
        if path == "/api/dashboard":
            self.send_json(HTTPStatus.OK, dashboard_data())
            return
        if path == "/api/audit":
            if actor["role"] != "auditor":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "La vista de auditoría requiere el rol auditor."})
                return
            self.send_json(HTTPStatus.OK, audit_data())
            return
        if path.startswith("/api/alerts/"):
            alert_id = path.rsplit("/", 1)[-1]
            if not alert_id.replace("-", "").isalnum() or len(alert_id) > 16:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Identificador inválido."})
                return
            result = alert_detail(alert_id)
            if not result:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "Alerta no encontrada."})
                return
            self.send_json(HTTPStatus.OK, result)
            return
        if path == "/api/users":
            if actor["role"] != "supervisor":
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Solo el supervisor puede consultar la lista de asignación."})
                return
            conn = database()
            try:
                users = [dict(row) for row in conn.execute(
                    "SELECT username, role FROM users WHERE role = 'analyst' ORDER BY username"
                ).fetchall()]
            finally:
                conn.close()
            self.send_json(HTTPStatus.OK, {"users": users})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "No encontrado."})

    def do_POST(self):
        if not self.check_origin():
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Origen no permitido."})
            return
        path = urlparse(self.path).path
        try:
            data = self.read_json()
        except ValueError as error:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        if path == "/api/login":
            username = str(data.get("username", "")).strip()
            password = data.get("password", "")
            if not isinstance(password, str) or len(username) > 80 or len(password) > 256:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Credenciales inválidas."})
                return
            user = authenticate(username, password)
            if not user:
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Credenciales incorrectas o cuenta temporalmente bloqueada."})
                return
            token = secrets.token_urlsafe(32)
            with SESSION_LOCK:
                SESSIONS[token] = {"user": user, "expires": time.time() + SESSION_HOURS * 3600}
            cookie = "session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}".format(
                token, SESSION_HOURS * 3600
            )
            self.send_json(HTTPStatus.OK, {"user": user}, {"Set-Cookie": cookie})
            return
        actor = self.get_actor()
        if not actor:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Inicie sesión para continuar."})
            return
        if path == "/api/logout":
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
                token = cookie["session"].value
                with SESSION_LOCK:
                    SESSIONS.pop(token, None)
            except (KeyError, CookieError):
                pass
            self.send_json(HTTPStatus.OK, {"ok": True}, {
                "Set-Cookie": "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            })
            return
        if path.startswith("/api/alerts/") and path.endswith("/actions"):
            alert_id = path.split("/")[-2]
            try:
                result = apply_action(alert_id, actor, str(data.get("action", "")), data)
            except LookupError as error:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": str(error)})
            except PermissionError as error:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": str(error)})
            except ValueError as error:
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            except sqlite3.Error:
                self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "No fue posible guardar la acción. Intente de nuevo."})
            else:
                self.send_json(HTTPStatus.OK, result)
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "No encontrado."})

    def serve_file(self, filename, content_type):
        try:
            body = (ROOT / filename).read_bytes()
        except OSError:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Recurso no encontrado."})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Método no permitido."})


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    initialize()
    try:
        server = LocalServer((HOST, PORT), Handler)
    except OSError as error:
        print("No se pudo iniciar el servidor local: {}".format(error), file=sys.stderr)
        return 1
    print("Tablero sintético disponible en http://{}:{}/".format(HOST, PORT), flush=True)
    print("Solo escucha en localhost; no exponga este prototipo a redes externas.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
