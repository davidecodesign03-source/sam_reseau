import ast
from pathlib import Path

SOURCE = Path('main.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)


def test_sos_routes_declared():
    expected = ['/sos', '/sos/{sos_id}', '/sos/{sos_id}/volontaire', '/sos/{sos_id}/accepter', '/sos/{sos_id}/refuser', '/sos/{sos_id}/annuler']
    for route in expected:
        assert repr(route) in SOURCE or '"' + route + '"' in SOURCE


def test_sos_single_active_per_emitter_constraint():
    assert 'sam_sos_un_actif_par_emetteur' in SOURCE, 'Add partial unique index to prevent duplicate active SOS'


def test_sos_creation_serialized():
    assert 'pg_advisory_xact_lock' in SOURCE, 'Serialize SOS creation for each sender'
