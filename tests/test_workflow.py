import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.cookiejar import CookieJar
from io import StringIO
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import server


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        server.DB_PATH = Path(self.temp_dir.name) / "alerts.sqlite3"
        server.PBKDF2_ROUNDS = 1_000
        with redirect_stdout(StringIO()):
            server.initialize()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_demo_dashboard_matches_document_totals(self):
        data = server.dashboard_data()
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
        before = len(server.alert_detail("AL-0192")["events"])
        with self.assertRaises(PermissionError):
            server.apply_action("AL-0192", actor, "close", {
                "reason": "Prueba de segregación",
                "evidence": "Regla SOC-01",
            })
        alert = server.alert_detail("AL-0192")
        self.assertEqual(alert["status"], "escalated")
        self.assertEqual(len(alert["events"]), before + 1)
        self.assertEqual(alert["events"][-1]["event_type"], "blocked")
        self.assertEqual(alert["events"][-1]["actor"], "analista.a")

    def test_assigned_analyst_cannot_approve_own_case_but_other_reviewer_can(self):
        payload = {"reason": "Aprobación de cierre", "evidence": "EV-REVIEW-01"}
        before = len(server.alert_detail("AL-0192")["events"])
        with self.assertRaises(PermissionError):
            server.apply_action(
                "AL-0192", {"username": "analista.a", "role": "analyst"},
                "approve_close", payload,
            )
        blocked = server.alert_detail("AL-0192")
        self.assertEqual(blocked["status"], "escalated")
        self.assertEqual(blocked["events"][-1]["event_type"], "blocked")
        self.assertEqual(len(blocked["events"]), before + 1)

        result = server.apply_action(
            "AL-0192", {"username": "revisor.e", "role": "reviewer"},
            "approve_close", payload,
        )
        self.assertEqual(result["status"], "closed")
        self.assertEqual(result["events"][-1]["actor"], "revisor.e")
        self.assertEqual(result["events"][-1]["reason"], payload["reason"])
        self.assertEqual(result["events"][-1]["evidence"], payload["evidence"])

    def test_missing_reason_or_evidence_does_not_change_state(self):
        with self.assertRaises(ValueError):
            server.apply_action("AL-0169", {"username": "supervisor.d", "role": "supervisor"},
                                "assign", {"assignee": "analista.a", "reason": "", "evidence": "EV-1"})
        self.assertEqual(server.alert_detail("AL-0169")["status"], "new")

    def test_auditor_cannot_perform_workflow_actions(self):
        with self.assertRaises(PermissionError):
            server.apply_action("AL-0163", {"username": "auditoria.p", "role": "auditor"},
                                "reopen", {"reason": "No permitido", "evidence": "EV-2"})
        self.assertEqual(server.alert_detail("AL-0163")["status"], "closed")

    def test_supervisor_reassignment_keeps_state_and_records_reason_and_evidence(self):
        result = server.apply_action(
            "AL-0181", {"username": "supervisor.d", "role": "supervisor"},
            "reassign", {
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
        salt, digest = server.password_hash("test-password")
        conn = server.database()
        try:
            conn.execute("UPDATE users SET salt = ?, password_hash = ?", (salt, digest))
            conn.commit()
        finally:
            conn.close()
        httpd = server.LocalServer((server.HOST, 0), server.Handler)
        base = "http://127.0.0.1:{}".format(httpd.server_address[1])
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        def client(username):
            opener = build_opener(HTTPCookieProcessor(CookieJar()))
            payload = json.dumps({"username": username, "password": "test-password"}).encode()
            request = Request(
                base + "/api/login", data=payload, method="POST",
                headers={"Content-Type": "application/json", "Origin": base},
            )
            opener.open(request, timeout=3).close()
            return opener

        def call(opener, path, origin=base, method="GET"):
            data = b"{}" if method == "POST" else None
            request = Request(
                base + path, data=data, method=method,
                headers={"Origin": origin, "Content-Type": "application/json"},
            )
            try:
                with opener.open(request, timeout=3) as response:
                    return response.status, json.loads(response.read())
            except HTTPError as error:
                error.close()
                return error.code, {}

        try:
            analyst = client("analista.a")
            self.assertEqual(call(analyst, "/api/audit")[0], 403)
            self.assertEqual(call(analyst, "/api/users")[0], 403)
            self.assertEqual(call(analyst, "/api/logout", "http://attacker.invalid", "POST")[0], 403)
            auditor = client("auditoria.p")
            status, data = call(auditor, "/api/audit")
            self.assertEqual(status, 200)
            self.assertEqual(len(data["exceptions"]), 2)
            self.assertEqual(len(data["overdue"]), 3)
            supervisor = client("supervisor.d")
            self.assertEqual(call(supervisor, "/api/users")[0], 200)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
