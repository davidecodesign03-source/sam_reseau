"""Non-destructive structural checks; integration tests still required before deployment."""
import ast
from pathlib import Path

SOURCE = Path("main.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCTIONS = {n.name: n for n in TREE.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def function_source(name):
    return ast.get_source_segment(SOURCE, FUNCTIONS[name])


def test_all_sos_routes_and_methods():
    expected = {
        ("post", "/sos"), ("get", "/sos"), ("get", "/sos/{sos_id}"),
        ("post", "/sos/{sos_id}/volontaire"),
        ("post", "/sos/{sos_id}/accepter"),
        ("post", "/sos/{sos_id}/refuser"),
        ("post", "/sos/{sos_id}/annuler"),
    }
    routes = set()
    for node in TREE.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            if not isinstance(decorator.func.value, ast.Name) or decorator.func.value.id != "app":
                continue
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                routes.add((decorator.func.attr.lower(), decorator.args[0].value))
    assert expected <= routes, f"Missing routes: {expected - routes}"


def test_single_active_sos_per_emitter_is_enforced_in_database():
    ddl = function_source("init_sos")
    assert "CREATE UNIQUE INDEX IF NOT EXISTS sam_sos_un_actif_par_emetteur" in ddl
    assert "ON sam_sos(emetteur_id)" in ddl
    for state in ("ouvert", "propose", "attribue"):
        assert state in ddl


def test_concurrent_creation_is_serialized():
    creation = function_source("sos_creer")
    assert "pg_advisory_xact_lock" in creation
    assert creation.index("pg_advisory_xact_lock") < creation.index("INSERT INTO sam_sos")


def test_volunteers_are_unique_and_candidate_selection_is_locked():
    ddl = function_source("init_sos")
    assert "PRIMARY KEY(sos_id,sam_id)" in ddl
    for name in ("sos_volontaire", "sos_decider", "sos_annuler"):
        assert "FOR UPDATE" in function_source(name)


def test_only_emitter_can_decide_and_cancel():
    assert "me!=emetteur" in function_source("sos_decider")
    assert "row[0]!=me" in function_source("sos_annuler")


def test_authentication_on_public_sos_handlers():
    for name in ("sos_creer", "sos_lister", "sos_detail", "sos_volontaire", "sos_decider", "sos_annuler"):
        assert "authenticated_sam" in function_source(name)


def test_sos_volunteer_restrictions():
    source = function_source("sos_volontaire")
    assert "row[0]==me" in source
    assert "('ouvert','propose')" in source


def test_sos_acceptance_and_refusal_paths():
    source = function_source("sos_decider")
    assert "etat='retenu'" in source
    assert "etat='refuse'" in source
    assert "sos_assign_next(cur,sos_id)" in source


def test_sos_reconnection_state():
    source = function_source("sos_detail")
    assert "ma_candidature" in source
    assert "je_suis_retenu" in source


def test_sos_offline_and_timeout_reassignment_guards():
    init = function_source("init_sos")
    assert "init_presence(conn)" in init
    assign = function_source("sos_assign_next")
    assert "sam_presence" in assign
    assert "30 seconds" in assign
    refresh = function_source("sos_refresh_candidate")
    assert "90" in refresh
    assert "sos_assign_next(cur, sos_id)" in refresh
    for handler in ("sos_detail", "sos_volontaire", "sos_decider"):
        assert "sos_refresh_candidate" in function_source(handler)
    assert "Samantha hors ligne" in function_source("sos_volontaire")


def test_sos_radio_link_requires_both_consents():
    ddl = function_source("init_sos")
    assert "init_liaisons(conn)" in ddl
    assert "ADD COLUMN IF NOT EXISTS liaison_id" in ddl
    decision = function_source("sos_decider")
    assert "pg_advisory_xact_lock" in decision
    assert "INSERT INTO sam_liaisons" in decision
    assert "etat='attribue'" in decision
    assert "liaison_id" in decision
    assert "Une demande de liaison est déjà en attente" in decision


def test_sos_cancellation_closes_only_dedicated_radio():
    ddl = function_source("init_sos")
    assert "liaison_sos_dediee" in ddl
    decision = function_source("sos_decider")
    assert "liaison_sos_dediee=False" in decision
    assert "liaison_sos_dediee=True" in decision
    cancel = function_source("sos_annuler")
    assert "if dediee and liaison_id is not None:" in cancel
    assert "UPDATE sam_liaisons SET etat='terminee'" in cancel
    assert "UPDATE sam_sos SET etat='annule'" in cancel
