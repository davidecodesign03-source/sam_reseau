"""Tests du client SOS sans connexion au réseau ni jeton réel."""
import io
from urllib import error

import pytest

import client_sos_v09 as sos


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.data


def test_https_and_token_required():
    with pytest.raises(ValueError):
        sos.SAMSOSClient("http://example.org", "secret")
    with pytest.raises(ValueError):
        sos.SAMSOSClient("https://example.org", "")


def test_full_sos_command_mapping(monkeypatch):
    requests = []

    def fake_open(req, timeout):
        requests.append((req.get_method(), req.full_url, req.data,
                         req.get_header("Authorization"), timeout))
        return FakeResponse(b'{"ok":true}')

    monkeypatch.setattr(sos.request, "urlopen", fake_open)
    client = sos.SAMSOSClient("https://example.org/", "test-private-token", timeout=3)
    calls = [
        (lambda: client.creer("Panne moteur"), "POST", "/sos"),
        (client.disponibles, "GET", "/sos"),
        (client.mon_actif, "GET", "/sos/mes/actif"),
        (client.mes_candidatures, "GET", "/sos/mes/candidatures"),
        (lambda: client.detail(42), "GET", "/sos/42"),
        (lambda: client.volontaire(42), "POST", "/sos/42/volontaire"),
        (lambda: client.accepter(42), "POST", "/sos/42/accepter"),
        (lambda: client.refuser(42), "POST", "/sos/42/refuser"),
        (lambda: client.annuler(42), "POST", "/sos/42/annuler"),
    ]
    for call, _, _ in calls:
        assert call() == {"ok": True}
    assert len(requests) == len(calls)
    for req, (_, method, path) in zip(requests, calls):
        assert req[0] == method
        assert req[1] == "https://example.org" + path
        assert req[3] == "Bearer test-private-token"
        assert req[4] == 3
    assert b"Panne moteur" in requests[0][2]


def test_http_errors_never_expose_token(monkeypatch):
    def fake_open(req, timeout):
        raise error.HTTPError(req.full_url, 403, "private-token-secret", {}, io.BytesIO(b"secret"))

    monkeypatch.setattr(sos.request, "urlopen", fake_open)
    client = sos.SAMSOSClient("https://example.org", "private-token-secret")
    with pytest.raises(sos.SAMSOSClientError) as raised:
        client.disponibles()
    assert raised.value.status == 403
    assert "private-token-secret" not in str(raised.value)


def test_network_failure_is_handled_without_token(monkeypatch):
    def fake_open(req, timeout):
        raise error.URLError("connection unavailable")

    monkeypatch.setattr(sos.request, "urlopen", fake_open)
    client = sos.SAMSOSClient("https://example.org", "secret")
    with pytest.raises(sos.SAMSOSClientError) as raised:
        client.mon_actif()
    assert raised.value.status == 0
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize("invalid", [0, -1, "not-a-number"])
def test_invalid_sos_ids_rejected(invalid):
    client = sos.SAMSOSClient("https://example.org", "secret")
    with pytest.raises(ValueError):
        client.accepter(invalid)
