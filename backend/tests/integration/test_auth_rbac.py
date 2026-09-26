def test_register_login_me(client, register):
    ctx = register(client, "founder@acme.io")
    assert ctx["me"]["organizations"][0]["role"] == "ADMIN"
    # Login returns tokens.
    resp = client.post("/api/v1/auth/login", json={
        "email": "founder@acme.io", "password": "correct horse battery"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_unauthenticated_is_rejected(client):
    assert client.get("/api/v1/organizations").status_code == 401


def test_invalid_token_rejected(client):
    resp = client.get("/api/v1/organizations",
                      headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_wrong_password_fails(client, register):
    register(client, "u@acme.io")
    resp = client.post("/api/v1/auth/login", json={"email": "u@acme.io", "password": "wrongwrong1"})
    assert resp.status_code == 401


def test_account_lockout_after_failed_logins(client, register):
    register(client, "lock@acme.io")
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": "lock@acme.io", "password": "badbadbad12"})
    # Even the correct password is now locked out.
    resp = client.post("/api/v1/auth/login",
                       json={"email": "lock@acme.io", "password": "correct horse battery"})
    assert resp.status_code == 423


def test_viewer_cannot_create_assets(client, register):
    admin = register(client, "admin@acme.io", org="Acme")
    org_id = admin["org_id"]
    # Register a second user, then add them as VIEWER.
    register(client, "viewer@acme.io", org="Viewer Personal Org")
    add = client.post(f"/api/v1/organizations/{org_id}/members",
                      headers=admin["headers"],
                      json={"email": "viewer@acme.io", "role": "VIEWER"})
    assert add.status_code == 201

    login = client.post("/api/v1/auth/login",
                        json={"email": "viewer@acme.io", "password": "correct horse battery"})
    vheaders = {"Authorization": f"Bearer {login.json()['access_token']}"}

    project = client.post(f"/api/v1/organizations/{org_id}/projects",
                          headers=admin["headers"], json={"name": "Prod"}).json()

    # Viewer can read...
    assert client.get(f"/api/v1/projects/{project['id']}", headers=vheaders).status_code == 200
    # ...but not create assets.
    resp = client.post(f"/api/v1/projects/{project['id']}/assets", headers=vheaders,
                       json={"type": "URL", "value": "http://example.com/"})
    assert resp.status_code == 403


def test_cannot_demote_last_admin(client, register):
    admin = register(client, "solo@acme.io", org="Solo")
    org_id = admin["org_id"]
    members = client.get(f"/api/v1/organizations/{org_id}/members",
                         headers=admin["headers"]).json()
    mid = members[0]["id"]
    resp = client.patch(f"/api/v1/organizations/{org_id}/members/{mid}",
                        headers=admin["headers"], json={"role": "VIEWER"})
    assert resp.status_code == 400
