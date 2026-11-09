"""Confirmation locale des intentions SOS dangereuses.

Aucun appel réseau ni accès au micro. L'intégration Samantha ED doit appeler
proposer() après une intention explicite, puis traiter_reponse() après une
nouvelle reconnaissance vocale. Une confirmation expire automatiquement.
"""
import time
from sos_intentions_v09 import _normaliser

_ACTIONS = frozenset({"preparer_sos", "preparer_annulation"})
_OUI = frozenset({"sam je confirme le sos", "samantha je confirme le sos",
                  "sam je confirme l annulation", "samantha je confirme l annulation"})
_NON = frozenset({"sam abandonne la confirmation", "samantha abandonne la confirmation",
                  "sam non annule la demande", "samantha non annule la demande"})


class ConfirmationSOS:
    def __init__(self, duree_secondes=15, horloge=None):
        if duree_secondes <= 0:
            raise ValueError("Duree de confirmation invalide")
        self.duree = duree_secondes
        self.horloge = horloge or time.monotonic
        self._action = None
        self._expiration = 0

    def proposer(self, action):
        if action not in _ACTIONS:
            raise ValueError("Action non confirmable")
        self._action = action
        self._expiration = self.horloge() + self.duree
        return "confirmation_requise"

    def traiter_reponse(self, phrase):
        action = self._action
        if action is None:
            return None
        if self.horloge() >= self._expiration:
            self.vider()
            return "confirmation_expiree"
        texte = _normaliser(phrase)
        if texte in _NON:
            self.vider()
            return "confirmation_abandonnee"
        if texte in _OUI:
            # Une confirmation d'annulation ne doit pas valider un envoi SOS.
            attendu = ("annulation" if action == "preparer_annulation" else "sos")
            if not texte.endswith(" " + attendu):
                return "confirmation_non_reconnue"
            self.vider()
            return "confirme_" + action
        return "confirmation_non_reconnue"

    def vider(self):
        self._action = None
        self._expiration = 0
