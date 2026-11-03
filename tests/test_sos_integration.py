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


def test_refusal_moves_to_next_volunteer(env_db):
    for name in ("a", "b", "c"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b, c = (auth("token-" + name) for name in ("a", "b", "c"))
    for who in (a, b, c):
        assert client.post("/presence", headers=who).status_code == 200
    sos_id = client.post("/sos", headers=a, json={"message": "Assistance"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    assert client.post(f"/sos/{sos_id}/volontaire", headers=c).status_code == 200
    refused = client.post(f"/sos/{sos_id}/refuser", headers=a)
    assert refused.status_code == 200, refused.text
    assert refused.json()["etat"] == "propose"
    assert client.get(f"/sos/{sos_id}", headers=b).status_code == 403
    assert client.get(f"/sos/{sos_id}", headers=c).status_code == 200
    accepted = client.post(f"/sos/{sos_id}/accepter", headers=a)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["liaison_id"]


def test_cancel_preserves_preexisting_accepted_radio(env_db):
    for name in ("a", "b"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b = auth("token-a"), auth("token-b")
    for who in (a, b):
        assert client.post("/presence", headers=who).status_code == 200
    with main.db() as conn:
        main.init_liaisons(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM samanthas WHERE installation_id=%s", ("installation-a",))
            aid = cur.fetchone()[0]
            cur.execute("SELECT id FROM samanthas WHERE installation_id=%s", ("installation-b",))
            bid = cur.fetchone()[0]
            cur.execute("""INSERT INTO sam_liaisons(demandeur_id,destinataire_id,etat)
                           VALUES (%s,%s,'acceptee') RETURNING id""", (aid,bid))
            existing_id = cur.fetchone()[0]
    sos_id = client.post("/sos", headers=a, json={"message": "Besoin d'aide"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    accepted = client.post(f"/sos/{sos_id}/accepter", headers=a)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["liaison_id"] == existing_id
    assert client.post(f"/sos/{sos_id}/annuler", headers=a).status_code == 200
    assert client.post(f"/liaisons/{existing_id}/messages", headers=b,
                       json={"texte": "liaison personnelle toujours active"}).status_code == 201


def test_expired_offer_moves_to_next_candidate(env_db):
    for name in ("a", "b", "c"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b, c = (auth("token-" + name) for name in ("a", "b", "c"))
    for who in (a, b, c):
        assert client.post("/presence", headers=who).status_code == 200
    sos_id = client.post("/sos", headers=a, json={"message": "Assistance urgente"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    assert client.post(f"/sos/{sos_id}/volontaire", headers=c).status_code == 200
    with main.db() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE sam_sos SET updated_at=now()-interval '2 minutes'
                           WHERE id=%s""", (sos_id,))
    detail = client.get(f"/sos/{sos_id}", headers=a)
    assert detail.status_code == 200, detail.text
    assert detail.json()["etat"] == "propose"
    assert client.get(f"/sos/{sos_id}", headers=b).status_code == 403
    assert client.post(f"/sos/{sos_id}/accepter", headers=a).status_code == 200


def test_unauthorized_decisions_and_cancel_are_rejected(env_db):
    for name in ("a", "b", "outsider"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b, outsider = (auth("token-" + name) for name in ("a", "b", "outsider"))
    for who in (a, b):
        assert client.post("/presence", headers=who).status_code == 200
    sos_id = client.post("/sos", headers=a, json={"message": "Panne moteur"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    for path in ("accepter", "refuser", "annuler"):
        assert client.post(f"/sos/{sos_id}/{path}", headers=outsider).status_code == 403
        assert client.post(f"/sos/{sos_id}/{path}", headers=b).status_code == 403
    assert client.post(f"/sos/{sos_id}/accepter", headers=a).status_code == 200
    assert client.post(f"/sos/{sos_id}/accepter", headers=a).status_code == 409


def test_parallel_acceptance_creates_one_radio_link(env_db):
    from concurrent.futures import ThreadPoolExecutor
    for name in ("a", "b"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b = auth("token-a"), auth("token-b")
    for who in (a, b):
        assert client.post("/presence", headers=who).status_code == 200
    sos_id = client.post("/sos", headers=a, json={"message": "Secours"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200

    def accept(_):
        return client.post(f"/sos/{sos_id}/accepter", headers=a)

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(accept, range(2)))
    assert sorted(r.status_code for r in responses) == [200, 409]
    with main.db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM sam_liaisons WHERE etat='acceptee'")
            assert cur.fetchone()[0] == 1


def test_recover_own_active_sos_after_reconnect(env_db):
    for name in ("a", "b"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b = auth("token-a"), auth("token-b")
    assert client.get("/sos/mes/actif", headers=a).json() == {"sos": None}
    assert client.post("/presence", headers=a).status_code == 200
    assert client.post("/presence", headers=b).status_code == 200
    created = client.post("/sos", headers=a, json={"message": "SOS persistant"})
    assert created.status_code == 201
    sos_id = created.json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    assert client.post("/presence/deconnexion", headers=a).status_code == 200
    assert client.post("/presence", headers=a).status_code == 200
    resumed = client.get("/sos/mes/actif", headers=a)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["sos"]["sos_id"] == sos_id
    assert resumed.json()["sos"]["message"] == "SOS persistant"
    assert client.get("/sos/mes/actif", headers=b).json() == {"sos": None}
    assert client.post("/sos", headers=a, json={"message": "double"}).status_code == 409
    assert client.post(f"/sos/{sos_id}/annuler", headers=a).status_code == 200
    assert client.get("/sos/mes/actif", headers=a).json() == {"sos": None}


def test_volunteer_recovers_own_status_without_private_leaks(env_db):
    for name in ("a", "b", "outsider"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b, outsider = (auth("token-" + name) for name in ("a", "b", "outsider"))
    for who in (a, b):
        assert client.post("/presence", headers=who).status_code == 200
    assert client.get("/sos/mes/candidatures", headers=b).json() == {"candidatures": []}
    sos_id = client.post("/sos", headers=a, json={"message": "Panne"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    # Nouvelle session HTTP : l'état est récupéré depuis PostgreSQL.
    client = TestClient(main.app)
    pending = client.get("/sos/mes/candidatures", headers=b)
    assert pending.status_code == 200, pending.text
    assert pending.json()["candidatures"][0]["sos_id"] == sos_id
    assert "message" not in pending.text
    assert client.get("/sos/mes/candidatures", headers=outsider).json() == {"candidatures": []}
    assert client.post(f"/sos/{sos_id}/accepter", headers=a).status_code == 200
    selected = client.get("/sos/mes/candidatures", headers=b).json()["candidatures"][0]
    assert selected["je_suis_retenu"] is True
    assert selected["liaison_id"]


def test_closing_dedicated_radio_reconciles_sos(env_db):
    for name in ("a", "b"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b = auth("token-a"), auth("token-b")
    for who in (a, b):
        assert client.post("/presence", headers=who).status_code == 200
    sos_id = client.post("/sos", headers=a, json={"message": "Besoin de secours"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200
    link_id = client.post(f"/sos/{sos_id}/accepter", headers=a).json()["liaison_id"]
    assert client.post(f"/liaisons/{link_id}/terminer", headers=b).status_code == 200
    # Aucun GET de réconciliation préalable : POST /sos doit se réparer lui-même.
    renewed = client.post("/sos", headers=a, json={"message": "Secours suivant"})
    assert renewed.status_code == 201, renewed.text
    assert renewed.json()["sos_id"] != sos_id
    assert client.post(f"/sos/{renewed.json()['sos_id']}/annuler", headers=a).status_code == 200
    assert client.get("/sos/mes/actif", headers=a).json() == {"sos": None}
    assert client.get(f"/sos/{sos_id}", headers=a).json()["etat"] == "annule"
    assert client.get("/sos/mes/candidatures", headers=b).json()["candidatures"] == []
    assert client.post(f"/liaisons/{link_id}/messages", headers=a,
                       json={"texte": "apres fermeture"}).status_code == 409
    # L'émetteur peut de nouveau lancer un secours.
    assert client.post("/sos", headers=a, json={"message": "Nouveau SOS"}).status_code == 201


def test_dedicated_radio_cannot_be_shared_between_active_sos(env_db):
    for name in ("a", "b"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b = auth("token-a"), auth("token-b")
    for who in (a, b):
        assert client.post("/presence", headers=who).status_code == 200
    first = client.post("/sos", headers=a, json={"message": "Premier secours"}).json()["sos_id"]
    assert client.post(f"/sos/{first}/volontaire", headers=b).status_code == 200
    first_radio = client.post(f"/sos/{first}/accepter", headers=a)
    assert first_radio.status_code == 200, first_radio.text
    second = client.post("/sos", headers=b, json={"message": "Second secours"}).json()["sos_id"]
    assert client.post(f"/sos/{second}/volontaire", headers=a).status_code == 200
    blocked = client.post(f"/sos/{second}/accepter", headers=b)
    assert blocked.status_code == 409, blocked.text
    assert client.get(f"/sos/{first}", headers=a).json()["etat"] == "attribue"
    assert client.post(f"/sos/{second}/annuler", headers=b).status_code == 200
    assert client.post(f"/sos/{first}/annuler", headers=a).status_code == 200


@pytest.mark.parametrize('round_number', range(5))
def test_parallel_regular_radio_request_and_sos_acceptance_no_duplicate(env_db, round_number):
    from concurrent.futures import ThreadPoolExecutor
    for name in ("a", "b"):
        register("token-" + name, "installation-" + name)
    client = TestClient(main.app)
    a, b = auth("token-a"), auth("token-b")
    for who in (a, b):
        assert client.post("/presence", headers=who).status_code == 200
    sos_id = client.post("/sos", headers=a, json={"message": "Radio urgente"}).json()["sos_id"]
    assert client.post(f"/sos/{sos_id}/volontaire", headers=b).status_code == 200

    def ordinary():
        return client.post("/liaisons", headers=a, json={"destinataire": "002"})

    def emergency():
        return client.post(f"/sos/{sos_id}/accepter", headers=a)

    with ThreadPoolExecutor(max_workers=2) as pool:
        normal_future = pool.submit(ordinary)
        sos_future = pool.submit(emergency)
        normal, urgent = normal_future.result(), sos_future.result()
    assert sorted([normal.status_code, urgent.status_code]) == [201, 409] or (
        normal.status_code == 409 and urgent.status_code == 200
    ), (normal.text, urgent.text)
    with main.db() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT COUNT(*) FROM sam_liaisons
                WHERE etat IN ('en_attente','acceptee')""")
            assert cur.fetchone()[0] == 1


def test_sos_end_to_end_two_samanthas_radio_exchange_and_cleanup(env_db):
    """Parcours réel API : alerte, volontaire, attribution, radio, fermeture."""
    register("token-originelle-test", "installation-originelle-test")
    register("token-secours-test", "installation-secours-test")
    client = TestClient(main.app)
    originelle = auth("token-originelle-test")
    secours = auth("token-secours-test")
    for headers in (originelle, secours):
        assert client.post("/presence", headers=headers).status_code == 200

    created = client.post("/sos", headers=originelle,
                          json={"message": "Assistance carburant demandee"})
    assert created.status_code == 201, created.text
    sos_id = created.json()["sos_id"]
    available = client.get("/sos", headers=secours)
    assert available.status_code == 200, available.text
    assert str(sos_id) in available.text
    assert "Assistance carburant demandee" not in available.text

    volunteer = client.post(f"/sos/{sos_id}/volontaire", headers=secours)
    assert volunteer.status_code == 200, volunteer.text
    accepted = client.post(f"/sos/{sos_id}/accepter", headers=originelle)
    assert accepted.status_code == 200, accepted.text
    liaison_id = accepted.json()["liaison_id"]
    assert liaison_id
    resumed = client.get("/sos/mes/candidatures", headers=secours)
    assert resumed.status_code == 200, resumed.text
    assert any(c["sos_id"] == sos_id and c["je_suis_retenu"]
               and c["liaison_id"] == liaison_id
               for c in resumed.json()["candidatures"])

    for headers, message in ((originelle, "Je suis en panne"),
                             (secours, "Je viens vous aider")):
        sent = client.post(f"/liaisons/{liaison_id}/messages",
                           headers=headers, json={"texte": message})
        assert sent.status_code == 201, sent.text
    for headers in (originelle, secours):
        received = client.get(f"/liaisons/{liaison_id}/messages", headers=headers)
        assert received.status_code == 200, received.text
        assert "Je suis en panne" in received.text
        assert "Je viens vous aider" in received.text

    cancelled = client.post(f"/sos/{sos_id}/annuler", headers=originelle)
    assert cancelled.status_code == 200, cancelled.text
    assert client.post(f"/liaisons/{liaison_id}/messages", headers=secours,
                       json={"texte": "Apres fermeture"}).status_code == 409
    assert client.get("/sos/mes/actif", headers=originelle).json() == {"sos": None}
