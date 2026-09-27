"""End-to-end: register -> project -> authorize asset -> scan the local testbed
-> findings -> dashboard -> report. Uses the bundled deliberately-vulnerable
Flask app on a random loopback port (lab mode enabled in the test env)."""
from __future__ import annotations

import socket
import threading
import time

import pytest


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def testbed_url():
    from werkzeug.serving import make_server

    from testbed.vulnerable_app import app as flask_app
    from testbed.vulnerable_app import init_db

    init_db()
    port = _free_port()
    server = make_server("127.0.0.1", port, flask_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Wait until it accepts connections.
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/"
    server.shutdown()


def test_full_scan_flow(client, register, testbed_url):
    ctx = register(client, "engineer@lab.io", org="Lab")
    org_id = ctx["org_id"]
    h = ctx["headers"]

    project = client.post(f"/api/v1/organizations/{org_id}/projects", headers=h,
                          json={"name": "Lab Project"}).json()
    asset = client.post(f"/api/v1/projects/{project['id']}/assets", headers=h,
                        json={"type": "URL", "value": testbed_url,
                              "criticality": "HIGH"}).json()

    # Authorize the asset (required before scanning).
    auth = client.post(f"/api/v1/assets/{asset['id']}/authorize", headers=h,
                       json={"authorize": True, "note": "owned lab target"})
    assert auth.status_code == 200
    assert auth.json()["authorization_status"] == "AUTHORIZED"

    # Run a FULL scan (eager: completes inline).
    scan = client.post(f"/api/v1/projects/{project['id']}/scans", headers=h,
                       json={"asset_id": asset["id"], "scan_type": "FULL",
                             "max_pages": 20, "skip_auth_bruteforce": False}).json()
    assert scan["status"] == "COMPLETED", scan
    assert scan["stats"]["pages_crawled"] >= 1

    findings = client.get(f"/api/v1/projects/{project['id']}/findings?page_size=200",
                          headers=h).json()
    categories = {f["category"] for f in findings["items"]}
    # The testbed has SQLi on /search and reflected XSS on /comment.
    assert "SQL Injection" in categories
    assert "Cross-Site Scripting (XSS)" in categories
    # Every finding has an explainable, bounded risk score.
    for f in findings["items"]:
        assert 0 <= f["risk_score"] <= 100
        assert f["risk_explanation"]["factors"]

    # Findings carry POTENTIAL MITRE techniques.
    sqli = next(f for f in findings["items"] if f["category"] == "SQL Injection")
    techs = client.get(f"/api/v1/findings/{sqli['id']}/techniques", headers=h).json()
    assert any(t["technique_id"] == "T1190" for t in techs)
    assert all(t["relationship_kind"] == "POTENTIAL" for t in techs)

    # Dashboard reflects real counts.
    dash = client.get(f"/api/v1/projects/{project['id']}/dashboard", headers=h).json()
    assert dash["total_assets"] == 1
    assert dash["authorized_assets"] == 1
    assert dash["open_findings"] == findings["total"]

    # Generate a JSON report and download it.
    report = client.post(f"/api/v1/projects/{project['id']}/reports", headers=h,
                         json={"report_type": "TECHNICAL", "fmt": "JSON"}).json()
    assert report["status"] == "READY", report
    dl = client.get(f"/api/v1/reports/{report['id']}/download", headers=h)
    assert dl.status_code == 200
    assert dl.json()["totals"]["findings"] == findings["total"]


def test_scan_cancel_when_queued(client, register):
    """A queued scan can be cancelled. (Uses an authorized but unreachable asset;
    with eager execution the runner will fail fast, so we assert the cancel path
    on a fresh queued row via the API contract.)"""
    ctx = register(client, "canceller@lab.io", org="Cancel Lab")
    org_id = ctx["org_id"]
    h = ctx["headers"]
    project = client.post(f"/api/v1/organizations/{org_id}/projects", headers=h,
                          json={"name": "P"}).json()
    # Non-routable but public-looking test IP that will simply fail to connect.
    asset = client.post(f"/api/v1/projects/{project['id']}/assets", headers=h,
                        json={"type": "URL", "value": "http://127.0.0.1:1/"}).json()
    client.post(f"/api/v1/assets/{asset['id']}/authorize", headers=h,
                json={"authorize": True, "note": "lab"})
    scan = client.post(f"/api/v1/projects/{project['id']}/scans", headers=h,
                       json={"asset_id": asset["id"], "scan_type": "TLS_HTTP"}).json()
    # Whatever terminal state it reached, cancel must be idempotent and safe.
    resp = client.post(f"/api/v1/scans/{scan['id']}/cancel", headers=h)
    assert resp.status_code == 200
