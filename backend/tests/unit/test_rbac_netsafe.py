import pytest
from app.core import rbac
from app.core.netsafe import TargetNotAllowed, validate_scan_url
from app.models.enums import Role


def test_viewer_is_read_only():
    perms = rbac.permissions_for(Role.VIEWER)
    assert rbac.ASSET_READ in perms
    assert rbac.ASSET_CREATE not in perms
    assert rbac.SCAN_CREATE not in perms
    assert rbac.USER_MANAGE not in perms


def test_analyst_can_operate_but_not_manage_users():
    perms = rbac.permissions_for(Role.SECURITY_ANALYST)
    assert rbac.SCAN_CREATE in perms
    assert rbac.ASSET_AUTHORIZE in perms
    assert rbac.REPORT_CREATE in perms
    assert rbac.USER_MANAGE not in perms
    assert rbac.SETTINGS_MANAGE not in perms


def test_admin_has_everything():
    assert rbac.permissions_for(Role.ADMIN) == rbac.ALL_PERMISSIONS


def test_ssrf_blocks_private_targets(monkeypatch):
    from app.core import netsafe
    monkeypatch.setattr(netsafe.settings, "allow_private_scan_targets", False)
    monkeypatch.setattr(netsafe, "resolve_host", lambda host: ["10.0.0.5"])
    with pytest.raises(TargetNotAllowed):
        validate_scan_url("http://internal.example/")


def test_scheme_must_be_http(monkeypatch):
    from app.core import netsafe
    monkeypatch.setattr(netsafe.settings, "allow_private_scan_targets", True)
    with pytest.raises(TargetNotAllowed):
        validate_scan_url("ftp://example.com/")


def test_private_allowed_in_lab_mode(monkeypatch):
    from app.core import netsafe
    monkeypatch.setattr(netsafe.settings, "allow_private_scan_targets", True)
    assert validate_scan_url("http://127.0.0.1:5000/") == "http://127.0.0.1:5000/"
