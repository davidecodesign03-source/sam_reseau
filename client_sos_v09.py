"""Client HTTP expérimental SOS V0.9 pour Samantha ED.

Module indépendant : aucune modification de l'application locale ni du serveur
de production. Ne jamais journaliser le jeton d'authentification.
"""
import json
from urllib import error, request


class SAMSOSClientError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


class SAMSOSClient:
    def __init__(self, base_url, token, timeout=8):
        if not base_url.startswith("https://"):
            raise ValueError("Une adresse HTTPS est obligatoire")
        if not token:
            raise ValueError("Jeton SAM manquant")
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout

    def _call(self, method, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.base_url + path, data=body, method=method,
            headers={"Authorization": "Bearer " + self._token,
                     "Content-Type": "application/json",
                     "Accept": "application/json"})
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            # Ne jamais renvoyer l'URL complète ou les en-têtes (jeton).
            raise SAMSOSClientError(exc.code, "Réponse SOS HTTP " + str(exc.code)) from None
        except (error.URLError, TimeoutError, OSError) as exc:
            raise SAMSOSClientError(0, "Serveur SOS temporairement inaccessible") from None

    @staticmethod
    def _id(sos_id):
        number = int(sos_id)
        if number <= 0:
            raise ValueError("Identifiant SOS invalide")
        return number

    def creer(self, message):
        return self._call("POST", "/sos", {"message": message})

    def disponibles(self):
        return self._call("GET", "/sos")

    def mon_actif(self):
        return self._call("GET", "/sos/mes/actif")

    def mes_candidatures(self):
        return self._call("GET", "/sos/mes/candidatures")

    def detail(self, sos_id):
        return self._call("GET", "/sos/" + str(self._id(sos_id)))

    def volontaire(self, sos_id):
        return self._call("POST", "/sos/" + str(self._id(sos_id)) + "/volontaire")

    def accepter(self, sos_id):
        return self._call("POST", "/sos/" + str(self._id(sos_id)) + "/accepter")

    def refuser(self, sos_id):
        return self._call("POST", "/sos/" + str(self._id(sos_id)) + "/refuser")

    def annuler(self, sos_id):
        return self._call("POST", "/sos/" + str(self._id(sos_id)) + "/annuler")
