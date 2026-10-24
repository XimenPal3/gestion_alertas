import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from backend.application import create_application
from backend.config import Settings
from backend.database import Database, POSTGRES_SCHEMA
from backend.http_api import create_app
from backend.security import LoginRateLimiter


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        settings = Settings(
            database_path=Path(self.temp_dir.name) / "alerts.sqlite3",
            static_root=ROOT / "src",
            password_iterations=1_000,
        )
        self.app = create_application(settings, output=lambda _message: None)
        self.service = self.app.alerts

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_demo_dashboard_matches_document_totals(self):
        data = self.service.dashboard()
        self.assertEqual(data["open"], 20)
        self.assertEqual(data["overdue"], 3)
        self.assertEqual(data["reopened"], 1)
        self.assertEqual(data["exception_count"], 2)
        self.assertEqual(sum(data["counts"].values()), 24)
        self.assertEqual(data["counts"]["new"], 5)
        self.assertEqual(data["counts"]["assigned"], 4)
        self.assertEqual(data["counts"]["analysis"], 7)
        self.assertEqual(data["counts"]["escalated"], 3)
        self.assertEqual(data["counts"]["closed"], 4)

    def test_assigned_analyst_cannot_close_critical_alert_and_attempt_is_audited(self):
        actor = {"username": "analista.a", "role": "analyst"}
        before = len(self.service.detail("AL-0192")["events"])
        with self.assertRaises(PermissionError):
            self.service.apply_action("AL-0192", actor, {
                "action": "close",
                "reason": "Prueba de segregación",
                "evidence": "Regla SOC-01",
            })
        alert = self.service.detail("AL-0192")
        self.assertEqual(alert["status"], "escalated")
        self.assertEqual(len(alert["events"]), before + 1)
        self.assertEqual(alert["events"][-1]["event_type"], "blocked")
        self.assertEqual(alert["events"][-1]["actor"], "analista.a")

    def test_assigned_analyst_cannot_approve_own_case_but_other_reviewer_can(self):
        payload = {"reason": "Aprobación de cierre", "evidence": "EV-REVIEW-01"}
        before = len(self.service.detail("AL-0192")["events"])
        with self.assertRaises(PermissionError):
            self.service.apply_action(
                "AL-0192", {"username": "analista.a", "role": "analyst"},
                {"action": "approve_close", **payload},
            )
        blocked = self.service.detail("AL-0192")
        self.assertEqual(blocked["status"], "escalated")
        self.assertEqual(blocked["events"][-1]["event_type"], "blocked")
        self.assertEqual(len(blocked["events"]), before + 1)

        result = self.service.apply_action(
            "AL-0192", {"username": "revisor.e", "role": "reviewer"},
            {"action": "approve_close", **payload},
        )
        self.assertEqual(result["status"], "closed")
        self.assertEqual(result["events"][-1]["actor"], "revisor.e")
        self.assertEqual(result["events"][-1]["reason"], payload["reason"])
        self.assertEqual(result["events"][-1]["evidence"], payload["evidence"])

    def test_missing_reason_or_evidence_does_not_change_state(self):
        with self.assertRaises(ValueError):
            self.service.apply_action("AL-0169", {"username": "supervisor.d", "role": "supervisor"},
                                      {"action": "assign", "assignee": "analista.a",
                                       "reason": "", "evidence": "EV-1"})
        self.assertEqual(self.service.detail("AL-0169")["status"], "new")

    def test_action_payload_types_are_validated(self):
        with self.assertRaisesRegex(ValueError, "El motivo debe ser texto"):
            self.service.apply_action("AL-0169", {"username": "supervisor.d", "role": "supervisor"}, {
                "action": "assign", "assignee": "analista.a",
                "reason": ["unexpected"], "evidence": "EV-1",
            })

    def test_auditor_cannot_perform_workflow_actions(self):
        with self.assertRaises(PermissionError):
            self.service.apply_action("AL-0163", {"username": "auditoria.p", "role": "auditor"},
                                      {"action": "reopen", "reason": "No permitido", "evidence": "EV-2"})
        self.assertEqual(self.service.detail("AL-0163")["status"], "closed")

    def test_supervisor_reassignment_keeps_state_and_records_reason_and_evidence(self):
        result = self.service.apply_action(
            "AL-0181", {"username": "supervisor.d", "role": "supervisor"},
            {"action": "reassign",
                "assignee": "analista.b",
                "reason": "Balanceo de carga",
                "evidence": "EV-REASSIGN-01",
            },
        )
        self.assertEqual(result["status"], "assigned")
        self.assertEqual(result["assigned_to"], "analista.b")
        self.assertEqual(result["events"][-1]["event_type"], "reassigned")
        self.assertEqual(result["events"][-1]["reason"], "Balanceo de carga")
        self.assertEqual(result["events"][-1]["evidence"], "EV-REASSIGN-01")

    def test_http_routes_enforce_audit_role_and_same_origin_writes(self):
        salt, digest = self.app.password_hasher.hash("test-password")
        with self.app.database.connection() as conn:
            conn.execute("UPDATE users SET salt = ?, password_hash = ?", (salt, digest))
            conn.commit()
        client = create_app(self.app).test_client()
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Gestión de alertas".encode("utf-8"), response.data)
        response.close()
        response = client.post("/api/login", json={
            "username": "analista.a", "password": "test-password",
        }, headers={"Origin": "http://localhost"})
        self.assertEqual(response.status_code, 200)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(client.get("/api/audit").status_code, 403)
        self.assertEqual(client.get("/api/users").status_code, 403)
        self.assertEqual(client.post(
            "/api/logout", json={}, headers={"Origin": "http://attacker.invalid"}
        ).status_code, 403)
        self.assertEqual(client.post("/api/logout", json={}).status_code, 403)
        self.assertEqual(client.post(
            "/api/logout", json={}, headers={"Origin": "http://localhost"}
        ).status_code, 200)
        self.assertEqual(client.get("/api/dashboard").status_code, 401)

        auditor = create_app(self.app).test_client()
        response = auditor.post("/api/login", json={
            "username": "auditoria.p", "password": "test-password",
        }, headers={"Origin": "http://localhost"})
        self.assertEqual(response.status_code, 200)
        response = auditor.get("/api/audit")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json["exceptions"]), 2)
        self.assertEqual(len(response.json["overdue"]), 3)

        supervisor = create_app(self.app).test_client()
        response = supervisor.post("/api/login", json={
            "username": "supervisor.d", "password": "test-password",
        }, headers={"Origin": "http://localhost"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(supervisor.get("/api/users").status_code, 200)

    def test_secure_cookie_mode_requires_https_and_sets_secure_attribute(self):
        secure_settings = Settings(
            database_path=Path(self.temp_dir.name) / "secure.sqlite3",
            static_root=ROOT / "src",
            password_iterations=1_000,
            cookie_secure=True,
        )
        secure_app = create_application(secure_settings, output=lambda _message: None)
        salt, digest = secure_app.password_hasher.hash("test-password")
        with secure_app.database.connection() as connection:
            connection.execute("UPDATE users SET salt = ?, password_hash = ?", (salt, digest))
            connection.commit()
        client = create_app(secure_app).test_client()
        response = client.post(
            "/api/login",
            base_url="https://faro.example",
            json={"username": "analista.a", "password": "test-password"},
            headers={"Origin": "https://faro.example"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Secure", response.headers["Set-Cookie"])
        rejected = client.post(
            "/api/logout",
            base_url="https://faro.example",
            json={},
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(rejected.status_code, 403)

    def test_login_rate_limit_and_session_expiration(self):
        limiter = LoginRateLimiter(self.app.database, max_attempts=2, lock_seconds=30)
        key = ("127.0.0.1", "unknown")
        limiter.failed(key, now=100)
        self.assertFalse(limiter.is_blocked(key, now=101))
        limiter.failed(key, now=102)
        self.assertTrue(limiter.is_blocked(key, now=103))
        self.assertFalse(limiter.is_blocked(key, now=133))

        token = self.app.create_session({"username": "analista.a", "role": "analyst"})
        self.assertEqual(self.app.get_actor(token)["username"], "analista.a")
        self.app.revoke_session(token)
        self.assertIsNone(self.app.get_actor(token))

    def test_sessions_and_login_limits_are_shared_between_app_instances(self):
        username_key = ("127.0.0.1", "unknown-user")
        for _ in range(self.app.settings.max_login_attempts):
            self.app.rate_limiter.failed(username_key)
        second_app = create_application(self.app.settings, output=lambda _message: None)
        self.assertTrue(second_app.rate_limiter.is_blocked(username_key))

        token = self.app.create_session({"username": "analista.a", "role": "analyst"})
        self.assertEqual(second_app.get_actor(token)["username"], "analista.a")
        second_app.revoke_session(token)
        self.assertIsNone(self.app.get_actor(token))

    def test_existing_sqlite_database_gets_new_session_and_rate_limit_tables(self):
        with self.app.database.connection() as connection:
            connection.execute("DROP TABLE sessions")
            connection.execute("DROP TABLE login_attempts")
            connection.commit()
        self.app.database.initialize()
        with self.app.database.connection() as connection:
            names = {
                row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            user_count = connection.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        self.assertIn("sessions", names)
        self.assertIn("login_attempts", names)
        self.assertEqual(user_count, 5)

    def test_postgres_schema_uses_supported_identity_column(self):
        self.assertIn("id BIGSERIAL PRIMARY KEY", POSTGRES_SCHEMA)
        self.assertNotIn("AUTOINCREMENT", POSTGRES_SCHEMA)

    def test_postgres_transactions_never_use_sqlite_begin_immediate(self):
        class FakePostgresConnection:
            def __init__(self):
                self.commands = []
                self.in_transaction = False
                self.committed = False
                self.closed = False

            def execute(self, statement):
                self.commands.append(statement)

            def commit(self):
                self.committed = True

            def rollback(self):
                self.in_transaction = False

            def close(self):
                self.closed = True

        database = Database(Path(self.temp_dir.name) / "unused.sqlite3", "postgresql://example")
        fake_connection = FakePostgresConnection()
        database.connect = lambda: fake_connection
        with database.transaction(immediate=True):
            pass
        self.assertEqual(fake_connection.commands, ["BEGIN"])
        self.assertTrue(fake_connection.committed)
        self.assertTrue(fake_connection.closed)

    def test_legacy_password_hash_is_upgraded_after_successful_login(self):
        password = "legacy-password"
        salt = b"test-salt-123456"
        legacy_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000).hex()
        with self.app.database.connection() as connection:
            connection.execute(
                "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
                (salt.hex(), legacy_hash, "analista.a"),
            )
            connection.commit()

        username = "analista.a"
        user = self.app.authenticate(username, password, "127.0.0.1")
        self.assertEqual(user["username"], username)
        upgraded = self.app.repository.find_user(username)
        self.assertNotEqual(upgraded["password_hash"], legacy_hash)
        self.assertTrue(self.app.password_hasher.verify(
            password, upgraded["salt"], upgraded["password_hash"]
        ))


if __name__ == "__main__":
    unittest.main()
