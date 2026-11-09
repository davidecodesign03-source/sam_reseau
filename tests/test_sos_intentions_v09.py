"""Vérifications des intentions SOS : aucune activation accidentelle."""
import pytest
from sos_intentions_v09 import reconnaitre_intention_sos


@pytest.mark.parametrize("phrase,intention", [
    ("Sam, lance un SOS !", "preparer_sos"),
    ("Samantha, j'ai besoin de secours", "preparer_sos"),
    ("Sam, demande de l'aide", "preparer_sos"),
    ("Samantha, consulte les SOS", "consulter_sos"),
    ("Sam, où en est mon SOS ?", "mon_sos"),
    ("Samantha, mes candidatures SOS", "mes_candidatures"),
    ("Sam, annule mon SOS", "preparer_annulation"),
])
def test_commandes_explicites(phrase, intention):
    assert reconnaitre_intention_sos(phrase) == intention


@pytest.mark.parametrize("phrase", [
    "SOS", "j'ai besoin d'aide", "sors le train", "Sam sors les armes",
    "Samantha allume les phares", "Sam annule", "Sam lance un son",
    "Sam lance un SOS pour quelqu'un", "", None,
])
def test_pas_de_declenchement_sur_phrase_ambigue(phrase):
    assert reconnaitre_intention_sos(phrase) is None
