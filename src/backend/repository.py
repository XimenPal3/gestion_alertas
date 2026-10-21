class AlertRepository:
    def __init__(self, database):
        self.database = database

    def find_user(self, username):
        with self.database.connection() as connection:
            return self.find_user_in(connection, username)

    @staticmethod
    def find_user_in(connection, username):
        row = connection.execute(
            "SELECT username, role, salt, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None

    def list_users(self, role=None):
        with self.database.connection() as connection:
            if role:
                rows = connection.execute(
                    "SELECT username, role FROM users WHERE role = ? ORDER BY username",
                    (role,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT username, role FROM users ORDER BY username"
                ).fetchall()
            return [dict(row) for row in rows]

    def update_password_hash(self, username, salt, digest):
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
                (salt, digest, username),
            )

    def list_alerts(self):
        with self.database.connection() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC"
            ).fetchall()]

    def get_alert(self, alert_id):
        with self.database.connection() as connection:
            return self.get_alert_in(connection, alert_id)

    @staticmethod
    def get_alert_in(connection, alert_id):
        row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def events_for_alert(self, alert_id):
        with self.database.connection() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM events WHERE alert_id = ? ORDER BY id", (alert_id,)
            ).fetchall()]

    def detail(self, alert_id):
        alert = self.get_alert(alert_id)
        if alert:
            alert["events"] = self.events_for_alert(alert_id)
        return alert

    def list_exceptions(self):
        with self.database.connection() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM exceptions ORDER BY code"
            ).fetchall()]

    def list_overdue(self, now):
        with self.database.connection() as connection:
            return [dict(row) for row in connection.execute(
                """SELECT * FROM alerts
                   WHERE status != 'closed' AND due_at < ?
                   ORDER BY due_at ASC""", (now,)
            ).fetchall()]

    def health_check(self):
        with self.database.connection() as connection:
            connection.execute("SELECT 1").fetchone()

    @staticmethod
    def add_event(connection, alert_id, actor, event_type, from_status,
                  to_status, reason, evidence, created_at):
        connection.execute(
            """INSERT INTO events
               (alert_id, actor, event_type, from_status, to_status, reason, evidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert_id, actor, event_type, from_status, to_status, reason, evidence, created_at),
        )

    @staticmethod
    def update_alert(connection, alert_id, status, assigned_to):
        connection.execute(
            "UPDATE alerts SET status = ?, assigned_to = ? WHERE id = ?",
            (status, assigned_to, alert_id),
        )
