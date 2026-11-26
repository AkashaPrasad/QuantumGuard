"""Built site at / with SPA fallback; API and health paths are never served from it."""

from fastapi.testclient import TestClient

from qg.testing import create_test_app


def test_static_site_and_fallback(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>QG</title>")
    (dist / "assets" / "app.js").write_text("console.log(1)")
    app = create_test_app(data_dir=tmp_path / "data", keys_dir=tmp_path / "keys")
    from qg.app import create_app

    core = app.state.core
    object.__setattr__(core.settings, "web_dist", dist)
    site = create_app(core)
    c = TestClient(site)
    assert c.get("/").text.startswith("<!doctype html>")
    assert c.get("/app/files/fil_x").text.startswith("<!doctype html>")
    assert c.get("/assets/app.js").text == "console.log(1)"
    r = c.get("/assets/app.js")
    assert r.headers["content-security-policy"].startswith("default-src 'self'")
    assert c.get("/api/v1/nope").json()["error"]["code"] == "QG_NOT_FOUND"
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/../../etc/passwd").text.startswith("<!doctype html>")
    assert c.post("/").status_code in (404, 405)


def test_unknown_paths_without_site(tmp_path):
    c = TestClient(create_test_app(data_dir=tmp_path / "data", keys_dir=tmp_path / "keys"))
    for method in ("GET", "POST", "DELETE"):
        r = c.request(method, "/api/v1/nope")
        assert r.status_code == 404 and r.json()["error"]["code"] == "QG_NOT_FOUND"
    assert c.get("/docs").status_code == 404 and c.get("/redoc").status_code == 404
