"""Intentions vocales SOS V0.9, indépendantes de Samantha ED.

Analyse uniquement : aucune requête réseau, aucune commande Elite et aucune
synthèse vocale n'est exécutée ici. L'intégration devra demander confirmation
avant d'envoyer un appel de détresse.
"""
import re
import unicodedata


def _normaliser(phrase):
    if not isinstance(phrase, str):
        return ""
    texte = unicodedata.normalize("NFKD", phrase.lower())
    texte = "".join(c for c in texte if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", texte)).strip()


_COMMANDES = {
    "preparer_sos": {
        "sam lance un sos", "samantha lance un sos",
        "sam demande de l aide", "samantha demande de l aide",
        "sam j ai besoin de secours", "samantha j ai besoin de secours",
        "sam envoie un sos", "samantha envoie un sos",
    },
    "consulter_sos": {
        "sam y a t il des sos", "samantha y a t il des sos",
        "sam consulte les sos", "samantha consulte les sos",
        "sam liste les sos", "samantha liste les sos",
    },
    "mon_sos": {
        "sam ou en est mon sos", "samantha ou en est mon sos",
        "sam statut de mon sos", "samantha statut de mon sos",
    },
    "mes_candidatures": {
        "sam mes candidatures sos", "samantha mes candidatures sos",
        "sam statut de mes secours", "samantha statut de mes secours",
    },
    "preparer_annulation": {
        "sam annule mon sos", "samantha annule mon sos",
        "sam annule l appel de detresse", "samantha annule l appel de detresse",
    },
}


def reconnaitre_intention_sos(phrase):
    """Renvoie une intention explicite ou None; aucune action n'est déclenchée."""
    texte = _normaliser(phrase)
    for intention, formulations in _COMMANDES.items():
        if texte in formulations:
            return intention
    return None
