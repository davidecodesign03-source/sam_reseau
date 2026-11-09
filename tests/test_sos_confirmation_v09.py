"""Tests de confirmation vocale SOS, sans micro ni réseau."""
import pytest
from sos_confirmation_v09 import ConfirmationSOS


def test_sos_ne_part_pas_sur_oui_simple():
    clock = [100]
    c = ConfirmationSOS(horloge=lambda: clock[0])
    assert c.proposer("preparer_sos") == "confirmation_requise"
    for phrase in ("oui", "je confirme", "sam oui", "Samantha je confirme l'annulation"):
        assert c.traiter_reponse(phrase) == "confirmation_non_reconnue"
    assert c.traiter_reponse("Sam, je confirme le SOS") == "confirme_preparer_sos"
    assert c.traiter_reponse("Sam, je confirme le SOS") is None


def test_annulation_exige_sa_propre_phrase():
    c = ConfirmationSOS()
    c.proposer("preparer_annulation")
    assert c.traiter_reponse("Sam je confirme le SOS") == "confirmation_non_reconnue"
    assert c.traiter_reponse("Samantha je confirme l'annulation") == "confirme_preparer_annulation"


def test_confirmation_expire():
    clock = [100]
    c = ConfirmationSOS(duree_secondes=15, horloge=lambda: clock[0])
    c.proposer("preparer_sos")
    clock[0] = 115
    assert c.traiter_reponse("Sam je confirme le SOS") == "confirmation_expiree"
    assert c.traiter_reponse("Sam je confirme le SOS") is None


def test_abandon_et_une_seule_validation():
    c = ConfirmationSOS()
    c.proposer("preparer_sos")
    assert c.traiter_reponse("Sam abandonne la confirmation") == "confirmation_abandonnee"
    assert c.traiter_reponse("Sam je confirme le SOS") is None


def test_action_inconnue_refusee():
    c = ConfirmationSOS()
    with pytest.raises(ValueError):
        c.proposer("ouvrir_les_armes")
    with pytest.raises(ValueError):
        ConfirmationSOS(duree_secondes=0)
