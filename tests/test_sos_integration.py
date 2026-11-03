"""Tests d'intégration SOS sur PostgreSQL jetable (jamais la production)."""
import hashlib
import os
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def env_db(monkeypatch):
    url = os.environ.get("SAM_TEST_DATABASE_URL")
    if not url:
        pytest.skip("SAM_TEST_DATABASE_URL absent : aucun test sur base réelle")
    # Isolation par schéma jetable, pour ne pas toucher aux tables d'autres tests.
    schema = "sos_test_" + uuid.uuid4().hex[:16]
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')
    try:
        monkeypatch.setenv("DATABASE_URL", url + ("&" if "?" in url else "?") +
                           "options=-csearch_path%3D" + schema)
        yield
    finally:
        with psycopg.connect(url, autocommit=True) as admin:
            admin.execute(f'DROP SCHEMA "{schema}" CASCADE')


def register(token, installation):
    with main.db() as conn:
        main.init_db(conn)
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO samanthas(installation_id,token_hash)
                VALUES (%s,%s)""", (installation, hashlib.sha256(token.encode()).hexdigest()))


def auth(token):
    return {"Authorization": "Bearer " + token}


def test_sos_privacy_reassignment_radio_and_cancel(env_db):
    for name in ("a", "b", "c", "outsider"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b, c, outsider = (auth("token-" + name) for name in ("a", "b", "c", "outsider"))
    for who in (a, b, c):
        assert client.post("/presence", headers=who).status_code == 200

    created = client.post("/sos", headers=a, json={"message": "Besoin de carburant"} )
    assert created.status_code == 201, created.text
    sos_id = created.json()["sos_id"]
    assert client.post("/sos", headers=a, json={"message": "double"}).status_code == 409
    directory = client.get("/sos", headers=outsider)
    assert directory.status_code == 200
    assert "message" not in directory.text
    assert client.get(f"/sos/{sos_id}", headers=outsider).status_code == 403

    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    assert client.post(f"/sos/{sos_id}/volontaire", headers=c).status_code == 200
    # B se déconnecte. La consultation déclenche la réattribution à C.
    assert client.post("/presence/deconnexion", headers=b).status_code == 200
    detail = client.get(f"/sos/{sos_id}", headers=a)
    assert detail.status_code == 200, detail.text
    assert detail.json()["etat"] == "propose"
    assert client.get(f"/sos/{sos_id}", headers=b).status_code == 403

    accepted = client.post(f"/sos/{sos_id}/accepter", headers=a)
    assert accepted.status_code == 200, accepted.text
    link_id = accepted.json()["liaison_id"]
    assert link_id
    assert client.get(f"/sos/{sos_id}", headers=c).json()["liaison_id"] == link_id
    assert client.post(f"/liaisons/{link_id}/messages", headers=outsider,
                       json={"texte": "intrusion"}).status_code == 404
    assert client.post(f"/liaisons/{link_id}/messages", headers=c,
                       json={"texte": "j'arrive"}).status_code == 201

    assert client.post(f"/sos/{sos_id}/annuler", headers=outsider).status_code == 403
    assert client.post(f"/sos/{sos_id}/annuler", headers=a).status_code == 200
    assert client.post(f"/liaisons/{link_id}/messages", headers=c,
                       json={"texte": "apres annulation"}).status_code == 409
