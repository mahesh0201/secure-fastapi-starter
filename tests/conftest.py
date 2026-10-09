import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

PASSWORD = "Str0ngPassword!23"


@pytest.fixture()
def settings(tmp_path):
    return Settings(db_path=str(tmp_path / "test.db"), secret_key="x" * 40)


@pytest.fixture()
def client(settings):
    return TestClient(create_app(settings))


def register_and_login(client, username="alice", password=PASSWORD):
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 201
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
