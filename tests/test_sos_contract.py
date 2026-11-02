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
