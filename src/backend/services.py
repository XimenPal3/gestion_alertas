from datetime import datetime, timezone


STATUS_LABELS = {
    "new": "Nueva",
    "assigned": "Asignada",
    "analysis": "En análisis",
    "escalated": "Escalada",
    "closed": "Cerrada",
    "reopened": "Reabierta",
}
ROLES = {
    "supervisor": "Supervisor",
    "analyst": "Analista",
    "reviewer": "Revisor",
    "auditor": "Auditoría",
}


def utc_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class AlertService:
    def __init__(self, database, repository):
        self.database = database
        self.repository = repository

    def dashboard(self):
        alerts = self.repository.list_alerts()
        counts = {status: 0 for status in STATUS_LABELS}
        open_alerts = []
        age_buckets = {"0-1": 0, "2-3": 0, "4-7": 0, ">7": 0}
        now = datetime.now(timezone.utc)
        overdue = 0
        for alert in alerts:
            counts[alert["status"]] += 1
            if alert["status"] == "closed":
                continue
            open_alerts.append(alert)
            created = datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00"))
            age_days = (now - created).total_seconds() / 86400
            age_buckets["0-1" if age_days < 2 else "2-3" if age_days < 4
                        else "4-7" if age_days <= 7 else ">7"] += 1
            if alert["due_at"] < utc_iso():
                overdue += 1
        return {
            "alerts": alerts,
            "counts": counts,
            "open": len(open_alerts),
            "overdue": overdue,
            "reopened": counts["reopened"],
            "exception_count": len(self.repository.list_exceptions()),
            "age_buckets": age_buckets,
        }

    def audit(self):
        now = utc_iso()
        return {
            "exceptions": self.repository.list_exceptions(),
            "overdue": self.repository.list_overdue(now),
        }

    def detail(self, alert_id):
        return self.repository.detail(alert_id)

    @staticmethod
    def _required_text(payload, name, label, limit):
        value = payload.get(name)
        if not isinstance(value, str):
            raise ValueError("{} debe ser texto.".format(label))
        value = value.strip()
        if not value or len(value) > limit:
            raise ValueError("{} es obligatorio (máximo {} caracteres).".format(label, limit))
        return value

    def apply_action(self, alert_id, actor, payload):
        if not isinstance(payload, dict):
            raise ValueError("El cuerpo debe ser un objeto JSON.")
        action = payload.get("action")
        if not isinstance(action, str):
            raise ValueError("Acción no reconocida.")
        reason = self._required_text(payload, "reason", "El motivo", 500)
        evidence = self._required_text(payload, "evidence", "La referencia de evidencia", 200)

        connection = self.database.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            alert = self.repository.get_alert_in(connection, alert_id)
            if not alert:
                raise LookupError("No existe esa alerta.")
            status, priority = alert["status"], alert["priority"]
            username, role = actor["username"], actor["role"]
            assigned_to = alert["assigned_to"]
            target_user = payload.get("assignee", "")
            if not isinstance(target_user, str):
                raise ValueError("Seleccione una cuenta activa con rol de analista.")
            target_user = target_user.strip()
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
                self._record_blocked(connection, alert, username,
                                     "Cierre crítico bloqueado: requiere aprobación de un revisor distinto.")
                connection.commit()
                raise PermissionError("Cierre bloqueado: el caso crítico requiere un segundo revisor.")
            if action in ("assign", "start") and status not in transitions[action][:2]:
                raise ValueError("La alerta no está en un estado válido para esta acción.")
            if action not in ("assign", "reassign", "start") and status != expected_status:
                raise ValueError("La alerta cambió de estado. Actualice el tablero e intente de nuevo.")

            if action in ("assign", "reassign"):
                if role != "supervisor":
                    raise PermissionError("Solo el supervisor puede asignar o reasignar alertas.")
                user = self.repository.find_user_in(connection, target_user)
                if not user or user["role"] != "analyst":
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
                    self._record_blocked(connection, alert, username,
                                         "Revisión propia bloqueada: el revisor es el analista asignado.")
                    connection.commit()
                    raise PermissionError("Segregación de funciones: el revisor debe ser distinto del analista.")
                if role != "reviewer":
                    raise PermissionError("Solo un revisor puede decidir una alerta escalada.")
                if action == "approve_close" and priority != "critical":
                    raise ValueError("La aprobación de segundo revisor es solo para alertas críticas.")
            elif action == "reopen":
                if role != "supervisor":
                    raise PermissionError("Solo el supervisor puede reabrir alertas.")

            event_type = (
                "assigned" if action == "assign" else
                "reassigned" if action == "reassign" else action
            )
            self.repository.update_alert(connection, alert_id, next_status, assigned_to)
            self.repository.add_event(
                connection, alert_id, username, event_type, status, next_status,
                reason, evidence, utc_iso(),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        return self.detail(alert_id)

    def _record_blocked(self, connection, alert, actor, reason):
        self.repository.add_event(
            connection, alert["id"], actor, "blocked", alert["status"], alert["status"],
            reason, "Control del sistema", utc_iso(),
        )
