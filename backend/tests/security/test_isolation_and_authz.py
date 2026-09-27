"""Security tests: cross-tenant isolation (IDOR), broken access control,
and the scan authorization gate."""


def _make_project_with_asset(client, ctx):
    org_id = ctx["org_id"]
    project = client.post(f"/api/v1/organizations/{org_id}/projects",
                          headers=ctx["headers"], json={"name": "P"}).json()
    asset = client.post(f"/api/v1/projects/{project['id']}/assets", headers=ctx["headers"],
                        json={"type": "URL", "value": "http://a.example/"}).json()
    return project, asset


def test_cross_tenant_project_access_is_404(client, register):
    a = register(client, "a@x.io", org="Org A")
    b = register(client, "b@y.io", org="Org B")
    project, asset = _make_project_with_asset(client, a)

    # B is not a member of A's org — must not see the project or asset.
    assert client.get(f"/api/v1/projects/{project['id']}", headers=b["headers"]).status_code == 404
    assert client.get(f"/api/v1/assets/{asset['id']}", headers=b["headers"]).status_code == 404
    # And cannot list A's org projects.
    assert client.get(f"/api/v1/organizations/{a['org_id']}/projects",
                      headers=b["headers"]).status_code == 404


def test_cross_tenant_mutation_blocked(client, register):
    a = register(client, "a2@x.io", org="Org A2")
    b = register(client, "b2@y.io", org="Org B2")
    project, asset = _make_project_with_asset(client, a)
    # B attempts to delete A's asset.
    assert client.delete(f"/api/v1/assets/{asset['id']}", headers=b["headers"]).status_code == 404


def test_scan_requires_authorized_asset(client, register):
    a = register(client, "scan@x.io", org="Scan Org")
    project, asset = _make_project_with_asset(client, a)
    # Asset defaults to UNAUTHORIZED — scanning must be refused.
    resp = client.post(f"/api/v1/projects/{project['id']}/scans", headers=a["headers"],
                       json={"asset_id": asset["id"], "scan_type": "TLS_HTTP"})
    assert resp.status_code == 403


def test_scan_other_projects_asset_rejected(client, register):
    a = register(client, "a3@x.io", org="Org A3")
    project_a, asset_a = _make_project_with_asset(client, a)
    project_b = client.post(f"/api/v1/organizations/{a['org_id']}/projects",
                            headers=a["headers"], json={"name": "B"}).json()
    # Asset from project_a cannot be scanned under project_b.
    resp = client.post(f"/api/v1/projects/{project_b['id']}/scans", headers=a["headers"],
                       json={"asset_id": asset_a["id"], "scan_type": "TLS_HTTP"})
    assert resp.status_code == 404
