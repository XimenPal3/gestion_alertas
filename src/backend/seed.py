import os
import secrets
from datetime import datetime, timedelta, timezone


DEMO_USERS = (
    ("supervisor.d", "supervisor"),
    ("analista.a", "analyst"),
    ("analista.b", "analyst"),
    ("revisor.e", "reviewer"),
    ("auditoria.p", "auditor"),
)

ALERTS = (
    ("AL-0192", "Movimientos inusuales en cuenta ficticia", "critical", "escalated", "analista.a", 0.25),
    ("AL-0188", "Transferencias en ráfaga", "high", "analysis", "analista.b", 1),
    ("AL-0181", "Cambio de datos de contacto", "medium", "assigned", "analista.a", 2),
    ("AL-0175", "Pagos fraccionados repetidos", "high", "analysis", "analista.c", 8),
    ("AL-0169", "Consulta de saldos atípicos", "low", "new", None, 0.125),
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
)


def utc_now():
    return datetime.now(timezone.utc)


def to_iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _add_event(connection, alert_id, actor, event_type, from_status, to_status, reason, evidence):
    connection.execute(
        """INSERT INTO events
           (alert_id, actor, event_type, from_status, to_status, reason, evidence, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (alert_id, actor, event_type, from_status, to_status, reason, evidence, to_iso(utc_now())),
    )


def seed_if_empty(database, password_hasher, output=print):
    with database.transaction(immediate=True) as connection:
        if database.is_postgres:
            connection.execute("SELECT pg_advisory_xact_lock(782134921)")
        user_count = connection.execute(
            "SELECT COUNT(*) AS total FROM users"
        ).fetchone()["total"]
        if user_count == 0:
            generated_passwords = []
            for username, role in DEMO_USERS:
                env_name = "DEMO_PASSWORD_" + username.upper().replace(".", "_")
                password = os.environ.get(env_name) or secrets.token_urlsafe(24)
                salt, digest = password_hasher.hash(password)
                connection.execute(
                    "INSERT INTO users (username, role, salt, password_hash) VALUES (?, ?, ?, ?)",
                    (username, role, salt, digest),
                )
                if not os.environ.get(env_name):
                    generated_passwords.append((username, password))
            if generated_passwords:
                output("\nCuentas sintéticas de demostración (guarde estas contraseñas):")
                for username, password in generated_passwords:
                    output("  {}: {}".format(username, password))
                output("Las credenciales no se pueden recuperar; elimine la base local para regenerarlas.\n")

        alert_count = connection.execute(
            "SELECT COUNT(*) AS total FROM alerts"
        ).fetchone()["total"]
        if alert_count != 0:
            return

        now = utc_now()
        sla_hours = {"critical": 12, "high": 120, "medium": 72, "low": 168}
        for alert_id, summary, priority, status, assigned, age_days in ALERTS:
            created = now - timedelta(days=age_days)
            due = created + timedelta(hours=sla_hours[priority])
            connection.execute(
                """INSERT INTO alerts
                   (id, summary, priority, status, assigned_to, created_at, due_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (alert_id, summary, priority, status, assigned, to_iso(created), to_iso(due)),
            )
            _add_event(connection, alert_id, "sistema", "created", None, "new",
                       "Alerta sintética generada por regla de demostración", "—")
            if status != "new":
                _add_event(connection, alert_id, "supervisor.d", "assigned", "new", "assigned",
                           "Asignación de demostración por rol y carga de trabajo", "EV-DEMO-01")
            if status in ("analysis", "escalated", "closed", "reopened"):
                _add_event(connection, alert_id, assigned or "analista.a", "started", "assigned",
                           "analysis", "Inicio de análisis sintético", "EV-DEMO-02")
            if status == "escalated":
                _add_event(connection, alert_id, assigned or "analista.a", "escalated",
                           "analysis", "escalated", "Requiere segundo revisor por prioridad", "EV-DEMO-03")
            if status == "closed":
                _add_event(connection, alert_id, assigned or "analista.a", "closed",
                           "analysis", "closed", "Cierre con justificación de demostración", "EV-DEMO-04")
            if status == "reopened":
                _add_event(connection, alert_id, "supervisor.d", "reopened", "closed", "reopened",
                           "Reapertura sintética para revisión", "EV-DEMO-05")

        _add_event(connection, "AL-0192", "analista.a", "blocked", "escalated", "escalated",
                   "Intento de cerrar un caso crítico propio bloqueado por segregación",
                   "Regla: segundo revisor distinto")
        connection.executemany(
            """INSERT INTO exceptions (code, alert_id, title, detail) VALUES (?, ?, ?, ?)""",
            [
                ("EXC-01", "AL-0163", "Cierre con justificación incompleta",
                 "Excepción sintética importada para revisión de auditoría."),
                ("EXC-02", "AL-0157", "Reasignación sin motivo registrado",
                 "Excepción sintética importada para revisión de auditoría."),
            ],
        )
