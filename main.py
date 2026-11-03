"""Réseau SAM V0.3 - inscriptions automatiques et identité Originelle réservée.

Variables Render : DATABASE_URL, SAM_ENROLLMENT_KEY.
Important : /register est public et ne prouve pas que le client est une vraie Samantha.
L'inscription Originelle est une opération initiale protégée, distincte de /register.
"""
import hashlib
import hmac
import logging
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="Réseau SAM", version="0.9.0-rc1")
logger = logging.getLogger("uvicorn.error")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def db():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise HTTPException(503, "Base de données non configurée")
    try:
        with psycopg.connect(url, connect_timeout=10) as conn:
            yield conn
    except psycopg.OperationalError as exc:
        # Diagnostic sans afficher de chaîne de connexion, de jeton ou de mot de passe.
        detail = str(exc).lower()
        if "password authentication failed" in detail or "authentication failed" in detail:
            reason = "authentication_failed"
        elif "tenant or user not found" in detail:
            reason = "pooler_user_not_found"
        elif "could not translate host name" in detail or "name or service not known" in detail:
            reason = "dns_resolution"
        elif "timeout" in detail or "timed out" in detail:
            reason = "connection_timeout"
        elif "connection refused" in detail:
            reason = "connection_refused"
        elif "network is unreachable" in detail:
            reason = "network_unreachable"
        elif "no pg_hba.conf entry" in detail:
            reason = "pg_hba_rejected"
        else:
            reason = "other_operational_error"
        logger.error("SAM_DATABASE_CONNECTION_FAILURE category=%s sqlstate=%s",
                     reason, getattr(exc, "sqlstate", None))
        raise HTTPException(503, "Base de données indisponible") from None


def init_db(conn):
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS samanthas (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            installation_id TEXT NOT NULL UNIQUE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        cur.execute("""ALTER TABLE samanthas
            ADD COLUMN IF NOT EXISTS is_originelle BOOLEAN NOT NULL DEFAULT FALSE""")
        cur.execute("""CREATE UNIQUE INDEX IF NOT EXISTS one_originelle_only
            ON samanthas (is_originelle) WHERE is_originelle = TRUE""")
        # Limite globale simple des nouvelles inscriptions : utile contre les rafales,
        # mais ce n'est PAS une vérification de l'authenticité du logiciel.
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_registration_limits (
            day DATE PRIMARY KEY, total INTEGER NOT NULL DEFAULT 0
        )""")


class Inscription(BaseModel):
    installation_id: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


def matricule(row_id: int, originelle: bool) -> str:
    return "ORIGINELLE" if originelle else f"{row_id:03d}"


@app.get("/")
def accueil():
    return {"service": "reseau-sam", "statut": "en_ligne", "version": "0.7.0"}


@app.get("/health")
def health():
    return {"ok": True}


def create_registration(payload: Inscription, originelle: bool):
    token = secrets.token_urlsafe(32)
    with db() as conn:
        init_db(conn)
        with conn.cursor() as cur:
            if not originelle:
                # Verrou transactionnel pour éviter de dépasser le plafond en concurrence.
                cur.execute("SELECT pg_advisory_xact_lock(30261019)")
                day = datetime.now(timezone.utc).date()
                cur.execute("""INSERT INTO sam_registration_limits(day,total)
                    VALUES (%s,0) ON CONFLICT(day) DO NOTHING""", (day,))
                cur.execute("SELECT total FROM sam_registration_limits WHERE day=%s FOR UPDATE", (day,))
                if cur.fetchone()[0] >= 100:
                    raise HTTPException(429, "Inscriptions temporairement limitées")
            else:
                cur.execute("SELECT id FROM samanthas WHERE is_originelle=TRUE")
                if cur.fetchone():
                    raise HTTPException(409, "Originelle est déjà enregistrée")
            cur.execute("""INSERT INTO samanthas(installation_id,token_hash,is_originelle)
                VALUES (%s,%s,%s) ON CONFLICT(installation_id) DO NOTHING
                RETURNING id""", (payload.installation_id, digest(token), originelle))
            row = cur.fetchone()
            if not row:
                raise HTTPException(409, "Installation déjà inscrite : utiliser son jeton existant")
            if not originelle:
                cur.execute("UPDATE sam_registration_limits SET total=total+1 WHERE day=%s", (day,))
    return {"matricule": matricule(row[0], originelle), "token": token,
            "message": "Conserver le jeton privé pour les prochaines connexions"}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def inscrire(payload: Inscription):
    """Inscription automatique des SAM ordinaires. Ne peut jamais créer Originelle."""
    return create_registration(payload, False)


@app.post("/register-originelle", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def inscrire_originelle(payload: Inscription, x_sam_enrollment_key: str | None = Header(default=None)):
    """Activation unique et protégée de l'instance fondatrice."""
    secret = os.getenv("SAM_ENROLLMENT_KEY", "")
    if not secret:
        raise HTTPException(503, "Activation Originelle non configurée")
    if not x_sam_enrollment_key or not hmac.compare_digest(x_sam_enrollment_key, secret):
        raise HTTPException(403, "Autorisation refusée")
    return create_registration(payload, True)


@app.get("/me")
def moi(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Jeton requis")
    token = authorization[7:]
    if not token:
        raise HTTPException(401, "Jeton requis")
    with db() as conn:
        init_db(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT id,is_originelle FROM samanthas WHERE token_hash=%s", (digest(token),))
            row = cur.fetchone()
    if not row:
        raise HTTPException(401, "Jeton invalide")
    return {"matricule": matricule(row[0], row[1]), "connecte": True}


# --- V0.4 : liaisons authentifiées et messages texte du réseau SAM ---
# Conservation de toutes les tables et identités V0.3.
from fastapi import Query

def authenticated_id(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Jeton requis")
    token = authorization[7:]
    if not token or len(token) > 512:
        raise HTTPException(401, "Jeton invalide")
    return digest(token)


def authenticated_sam(conn, authorization):
    with conn.cursor() as cur:
        cur.execute("SELECT id, is_originelle FROM samanthas WHERE token_hash=%s",
                    (authenticated_id(authorization),))
        row = cur.fetchone()
    if not row:
        raise HTTPException(401, "Jeton invalide")
    return row[0], matricule(row[0], row[1])


def init_liaisons(conn):
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_liaisons (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            demandeur_id BIGINT NOT NULL REFERENCES samanthas(id),
            destinataire_id BIGINT NOT NULL REFERENCES samanthas(id),
            etat TEXT NOT NULL DEFAULT 'en_attente'
                CHECK (etat IN ('en_attente','acceptee','refusee','terminee')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_messages (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            liaison_id BIGINT NOT NULL REFERENCES sam_liaisons(id),
            auteur_id BIGINT NOT NULL REFERENCES samanthas(id),
            texte TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        cur.execute("""CREATE INDEX IF NOT EXISTS sam_liaisons_demandeur
                       ON sam_liaisons(demandeur_id, id DESC)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS sam_liaisons_destinataire
                       ON sam_liaisons(destinataire_id, id DESC)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS sam_messages_liaison
                       ON sam_messages(liaison_id, id)""")


class DemandeLiaison(BaseModel):
    destinataire: str = Field(min_length=3, max_length=24)


class MessageLiaison(BaseModel):
    texte: str = Field(min_length=1, max_length=500)


def find_sam(conn, label):
    with conn.cursor() as cur:
        if label.upper() == "ORIGINELLE":
            cur.execute("SELECT id FROM samanthas WHERE is_originelle=TRUE")
        elif label.isdecimal() and 1 <= len(label) <= 12:
            cur.execute("SELECT id FROM samanthas WHERE id=%s AND is_originelle=FALSE",
                        (int(label),))
        else:
            raise HTTPException(422, "Matricule destinataire invalide")
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Destinataire inconnu")
    return row[0]


def liaison_row(conn, liaison_id, my_id, lock=False):
    with conn.cursor() as cur:
        cur.execute("""SELECT id, demandeur_id, destinataire_id, etat
                       FROM sam_liaisons WHERE id=%s
                       AND (demandeur_id=%s OR destinataire_id=%s)""" +
                    (" FOR UPDATE" if lock else ""),
                    (liaison_id, my_id, my_id))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Liaison introuvable")
    return row


def liaison_json(row, labels):
    return {"liaison_id": row[0], "demandeur": labels[row[1]],
            "destinataire": labels[row[2]], "etat": row[3]}


def labels_for(conn, ids):
    if not ids:
        return {}
    with conn.cursor() as cur:
        cur.execute("SELECT id, is_originelle FROM samanthas WHERE id = ANY(%s)",
                    (list(ids),))
        return {r[0]: matricule(r[0], r[1]) for r in cur.fetchall()}


@app.post("/liaisons", status_code=201)
def demander_liaison(payload: DemandeLiaison,
                    authorization: str | None = Header(default=None)):
    with db() as conn:
        init_liaisons(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        target_id = find_sam(conn, payload.destinataire.strip())
        if target_id == me_id:
            raise HTTPException(400, "Une Samantha ne peut pas s'appeler elle-même")
        with conn.cursor() as cur:
            # Verrou transactionnel par couple, pour éviter les doubles demandes.
            a, b = sorted((me_id, target_id))
            cur.execute("SELECT pg_advisory_xact_lock(%s, %s)", (int(a), int(b)))
            cur.execute("""SELECT id FROM sam_liaisons
                           WHERE ((demandeur_id=%s AND destinataire_id=%s)
                               OR (demandeur_id=%s AND destinataire_id=%s))
                           AND etat IN ('en_attente','acceptee')
                           ORDER BY id DESC LIMIT 1""",
                        (me_id, target_id, target_id, me_id))
            if cur.fetchone():
                raise HTTPException(409, "Une liaison est déjà en cours")
            cur.execute("""INSERT INTO sam_liaisons(demandeur_id,destinataire_id)
                           VALUES (%s,%s) RETURNING id""", (me_id, target_id))
            liaison_id = cur.fetchone()[0]
    return {"liaison_id": liaison_id, "etat": "en_attente"}


@app.get("/liaisons")
def lister_liaisons(authorization: str | None = Header(default=None)):
    with db() as conn:
        init_liaisons(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("""SELECT id,demandeur_id,destinataire_id,etat FROM sam_liaisons
                           WHERE demandeur_id=%s OR destinataire_id=%s
                           ORDER BY id DESC LIMIT 50""", (me_id, me_id))
            rows = cur.fetchall()
        labels = labels_for(conn, {id for r in rows for id in r[1:3]})
    return {"liaisons": [liaison_json(row, labels) for row in rows]}


def changer_etat(liaison_id, authorization, action):
    with db() as conn:
        init_liaisons(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        row = liaison_row(conn, liaison_id, me_id, lock=True)
        _, demandeur, destinataire, etat = row
        if action in ("acceptee", "refusee"):
            if me_id != destinataire:
                raise HTTPException(403, "Seul le destinataire peut répondre")
            if etat != "en_attente":
                raise HTTPException(409, "Demande déjà traitée")
        elif etat not in ("en_attente", "acceptee"):
            raise HTTPException(409, "Liaison déjà close")
        with conn.cursor() as cur:
            cur.execute("""UPDATE sam_liaisons SET etat=%s,updated_at=now()
                           WHERE id=%s""", (action, liaison_id))
    return {"liaison_id": liaison_id, "etat": action}


@app.post("/liaisons/{liaison_id}/accepter")
def accepter_liaison(liaison_id: int, authorization: str | None = Header(default=None)):
    return changer_etat(liaison_id, authorization, "acceptee")


@app.post("/liaisons/{liaison_id}/refuser")
def refuser_liaison(liaison_id: int, authorization: str | None = Header(default=None)):
    return changer_etat(liaison_id, authorization, "refusee")


@app.post("/liaisons/{liaison_id}/terminer")
def terminer_liaison(liaison_id: int, authorization: str | None = Header(default=None)):
    return changer_etat(liaison_id, authorization, "terminee")


@app.post("/liaisons/{liaison_id}/messages", status_code=201)
def envoyer_message(liaison_id: int, payload: MessageLiaison,
                    authorization: str | None = Header(default=None)):
    with db() as conn:
        init_liaisons(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        row = liaison_row(conn, liaison_id, me_id, lock=True)
        if row[3] != "acceptee":
            raise HTTPException(409, "Liaison non acceptée")
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO sam_messages(liaison_id,auteur_id,texte)
                           VALUES (%s,%s,%s) RETURNING id""",
                        (liaison_id, me_id, payload.texte))
            message_id = cur.fetchone()[0]
    return {"message_id": message_id}


@app.get("/liaisons/{liaison_id}/messages")
def recevoir_messages(liaison_id: int, apres: int = Query(default=0, ge=0),
                      authorization: str | None = Header(default=None)):
    with db() as conn:
        init_liaisons(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        row = liaison_row(conn, liaison_id, me_id)
        if row[3] != "acceptee":
            raise HTTPException(409, "Liaison non acceptée")
        with conn.cursor() as cur:
            cur.execute("""SELECT id,auteur_id,texte FROM sam_messages
                           WHERE liaison_id=%s AND id>%s
                           ORDER BY id LIMIT 100""", (liaison_id, apres))
            rows = cur.fetchall()
        labels = labels_for(conn, {r[1] for r in rows})
    return {"messages": [{"message_id": r[0], "auteur": labels[r[1]], "texte": r[2]}
                         for r in rows]}


# --- V0.5 : présence réelle des Samantha (heartbeat, expiration automatique) ---
from datetime import timedelta

def init_presence(conn):
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_presence (
            sam_id BIGINT PRIMARY KEY REFERENCES samanthas(id) ON DELETE CASCADE,
            last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")

@app.post("/presence")
def signaler_presence(authorization: str | None = Header(default=None)):
    with db() as conn:
        init_presence(conn)
        my_id, my_label = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO sam_presence(sam_id,last_seen)
                           VALUES (%s,now()) ON CONFLICT(sam_id)
                           DO UPDATE SET last_seen=now()""", (my_id,))
    return {"matricule": my_label, "en_ligne": True}

@app.get("/contacts")
def contacts_en_ligne(authorization: str | None = Header(default=None)):
    with db() as conn:
        init_presence(conn)
        my_id, _ = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("""SELECT s.id,s.is_originelle FROM sam_presence p
                           JOIN samanthas s ON s.id=p.sam_id
                           WHERE p.sam_id<>%s AND p.last_seen > now()-interval '30 seconds'
                           ORDER BY s.is_originelle DESC,s.id ASC LIMIT 100""", (my_id,))
            rows = cur.fetchall()
    return {"contacts": [{"matricule": matricule(r[0],r[1]), "en_ligne": True}
                         for r in rows]}


@app.post("/presence/deconnexion")
def quitter_reseau(authorization: str | None = Header(default=None)):
    with db() as conn:
        init_presence(conn)
        my_id, _ = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sam_presence WHERE sam_id=%s", (my_id,))
    return {"en_ligne": False}


# --- V0.7 : audio différé, une transmission à la fois ---
# Le contenu MP3 est stocké dans PostgreSQL pour survivre aux redémarrages Render.
import base64
import binascii
import subprocess
import tempfile
import random
from pathlib import Path

def sam_server_radio(mp3: bytes) -> bytes:
    """Un seul traitement radio, au serveur. Retour original si conversion impossible."""
    try:
        import imageio_ffmpeg
        ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
        with tempfile.TemporaryDirectory(prefix="sam_radio_") as td:
            source = Path(td) / "entree.mp3"
            output = Path(td) / "radio.mp3"
            source.write_bytes(mp3)
            # Parasites brefs à des instants variables, sans rendre la parole inaudible.
            rng = random.Random(hashlib.sha256(mp3).digest())
            delays = sorted(rng.randint(900, 4700) for _ in range(3))
            # La voix garde la priorité; souffle continu et trois éclats discrets.
            graph = (
                "[0:a]highpass=f=420,lowpass=f=2450,"
                "acompressor=threshold=-24dB:ratio=4:attack=3:release=85,"
                "acrusher=bits=11:mode=lin,volume=0.93[v];"
                "[1:a]volume=0.055[n];"
                + ''.join(f"[{i+2}:a]volume=0.19,atrim=duration=0.10,adelay={d}|{d}[b{i}];" for i,d in enumerate(delays))
                + "[v][n][b0][b1][b2]amix=inputs=5:duration=first:normalize=0,"
                  "alimiter=limit=0.92[out]"
            )
            cmd = [ffmpeg, '-nostdin', '-hide_banner', '-loglevel', 'error', '-y',
                   '-i', str(source),
                   '-f', 'lavfi', '-i', 'anoisesrc=color=pink:amplitude=0.12:sample_rate=44100',
                   '-f', 'lavfi', '-i', 'anoisesrc=color=white:amplitude=0.4:sample_rate=44100',
                   '-f', 'lavfi', '-i', 'anoisesrc=color=white:amplitude=0.4:sample_rate=44100',
                   '-f', 'lavfi', '-i', 'anoisesrc=color=white:amplitude=0.4:sample_rate=44100',
                   '-filter_complex', graph, '-map', '[out]', '-ac', '1',
                   '-codec:a', 'libmp3lame', '-b:a', '80k', str(output)]
            result = subprocess.run(cmd, capture_output=True, timeout=45)
            if result.returncode:
                raise RuntimeError(result.stderr.decode('utf-8', 'replace')[-500:])
            processed = output.read_bytes()
            if not (100 <= len(processed) <= 1_500_000):
                raise ValueError('MP3 traité hors limite')
            return processed
    except Exception as exc:
        logger.warning('SAM_RADIO_FALLBACK %s', str(exc)[:300])
        return mp3


class AudioTransmission(BaseModel):
    audio_b64: str = Field(min_length=1, max_length=2100000)
    nom: str = Field(default="transmission.mp3", max_length=100)

def init_audio(conn):
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_audio_transmissions (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            liaison_id BIGINT NOT NULL REFERENCES sam_liaisons(id) ON DELETE CASCADE,
            auteur_id BIGINT NOT NULL REFERENCES samanthas(id),
            audio BYTEA NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")

@app.post("/liaisons/{liaison_id}/audio", status_code=201)
def envoyer_audio(liaison_id: int, payload: AudioTransmission,
                  authorization: str | None = Header(default=None)):
    try:
        audio = base64.b64decode(payload.audio_b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, "Audio base64 invalide")
    if not (100 <= len(audio) <= 1500000):
        raise HTTPException(413, "Audio trop volumineux ou vide (1,5 Mo maximum)")
    if not audio.startswith(b"ID3") and audio[:2] not in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        raise HTTPException(415, "MP3 attendu")
    # Valider le client et sa liaison AVANT le traitement FFmpeg coûteux.
    with db() as conn:
        init_liaisons(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        row = liaison_row(conn, liaison_id, me_id)
        if row[3] != "acceptee":
            raise HTTPException(409, "Liaison non acceptée")
    audio = sam_server_radio(audio)
    with db() as conn:
        init_liaisons(conn)
        init_audio(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        row = liaison_row(conn, liaison_id, me_id, lock=True)
        if row[3] != "acceptee":
            raise HTTPException(409, "Liaison non acceptée")
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO sam_audio_transmissions(liaison_id,auteur_id,audio)
                           VALUES (%s,%s,%s) RETURNING id""",
                        (liaison_id, me_id, audio))
            transmission_id = cur.fetchone()[0]
    return {"transmission_id": transmission_id}

@app.get("/liaisons/{liaison_id}/audio")
def recevoir_audio(liaison_id: int, apres: int = Query(default=0, ge=0),
                   authorization: str | None = Header(default=None)):
    with db() as conn:
        init_liaisons(conn)
        init_audio(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        row = liaison_row(conn, liaison_id, me_id)
        if row[3] != "acceptee":
            raise HTTPException(409, "Liaison non acceptée")
        with conn.cursor() as cur:
            cur.execute("""SELECT id,auteur_id,audio FROM sam_audio_transmissions
                           WHERE liaison_id=%s AND id>%s ORDER BY id LIMIT 4""",
                        (liaison_id, apres))
            rows = cur.fetchall()
        labels = labels_for(conn, {r[1] for r in rows})
    return {"transmissions": [
        {"transmission_id": r[0], "auteur": labels[r[1]],
         "audio_b64": base64.b64encode(bytes(r[2])).decode("ascii")}
        for r in rows]}

# --- Réseau SAM : secours V0.9 (prototype non déployé) ---
class SOSCreation(BaseModel):
    message: str = Field(min_length=1, max_length=500)

def init_sos(conn):
    init_db(conn)
    init_presence(conn)
    init_liaisons(conn)
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_sos (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            emetteur_id BIGINT NOT NULL REFERENCES samanthas(id),
            message TEXT NOT NULL,
            etat TEXT NOT NULL DEFAULT 'ouvert'
                CHECK (etat IN ('ouvert','propose','attribue','annule')),
            candidat_id BIGINT REFERENCES samanthas(id),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_sos_volontaires (
            sos_id BIGINT NOT NULL REFERENCES sam_sos(id),
            sam_id BIGINT NOT NULL REFERENCES samanthas(id),
            etat TEXT NOT NULL DEFAULT 'en_attente'
                CHECK (etat IN ('en_attente','refuse','retenu')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY(sos_id,sam_id)
        )""")
        cur.execute("""CREATE UNIQUE INDEX IF NOT EXISTS sam_sos_un_actif_par_emetteur
            ON sam_sos(emetteur_id) WHERE etat IN ('ouvert','propose','attribue')""")
        cur.execute("""ALTER TABLE sam_sos ADD COLUMN IF NOT EXISTS liaison_id
            BIGINT REFERENCES sam_liaisons(id)""")
        cur.execute("""ALTER TABLE sam_sos ADD COLUMN IF NOT EXISTS liaison_sos_dediee
            BOOLEAN NOT NULL DEFAULT FALSE""")
        cur.execute("""CREATE INDEX IF NOT EXISTS sam_sos_volontaires_ordre
            ON sam_sos_volontaires(sos_id,created_at,sam_id)""")

# V0.9 : un candidat doit être présent sur le réseau (heartbeat < 30 s).
# Les transitions s'effectuent sous verrou FOR UPDATE sur sam_sos.
def sos_assign_next(cur, sos_id):
    cur.execute("""UPDATE sam_sos_volontaires v SET etat='refuse'
                   WHERE v.sos_id=%s AND v.etat='en_attente'
                   AND NOT EXISTS (
                       SELECT 1 FROM sam_presence p WHERE p.sam_id=v.sam_id
                       AND p.last_seen > now()-interval '30 seconds'
                   )""", (sos_id,))
    cur.execute("""SELECT v.sam_id FROM sam_sos_volontaires v
                   JOIN sam_presence p ON p.sam_id=v.sam_id
                   WHERE v.sos_id=%s AND v.etat='en_attente'
                   AND p.last_seen > now()-interval '30 seconds'
                   ORDER BY v.created_at,v.sam_id LIMIT 1""", (sos_id,))
    row = cur.fetchone()
    if row:
        cur.execute("""UPDATE sam_sos SET etat='propose', candidat_id=%s,
                       updated_at=now() WHERE id=%s""", (row[0],sos_id))
        return row[0]
    cur.execute("""UPDATE sam_sos SET etat='ouvert', candidat_id=NULL,
                   updated_at=now() WHERE id=%s""", (sos_id,))
    return None


def sos_refresh_candidate(cur, sos_id):
    """Réattribue une proposition expirée ou dont le volontaire est hors ligne.

    Appeler après verrouillage de la ligne sam_sos (FOR UPDATE).
    Expiration évaluée lors des requêtes, sans tâche de fond.
    """
    cur.execute("""SELECT etat,candidat_id,updated_at FROM sam_sos
                   WHERE id=%s""", (sos_id,))
    row = cur.fetchone()
    if not row or row[0] != 'propose' or row[1] is None:
        return
    state, candidate, updated = row
    cur.execute("""SELECT EXISTS(
                   SELECT 1 FROM sam_presence
                   WHERE sam_id=%s AND last_seen > now()-interval '30 seconds'
                   )""", (candidate,))
    online = cur.fetchone()[0]
    expired = (datetime.now(timezone.utc) - updated).total_seconds() > 90
    if not online or expired:
        cur.execute("""UPDATE sam_sos_volontaires SET etat='refuse'
                       WHERE sos_id=%s AND sam_id=%s AND etat='en_attente'""",
                    (sos_id, candidate))
        sos_assign_next(cur, sos_id)

@app.post("/sos", status_code=201)
def sos_creer(payload: SOSCreation, authorization: str | None = Header(default=None)):
    with db() as conn:
        init_sos(conn)
        me, _ = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (me,))
            cur.execute("""SELECT id FROM sam_sos WHERE emetteur_id=%s
                AND etat IN ('ouvert','propose','attribue') LIMIT 1""", (me,))
            if cur.fetchone():
                raise HTTPException(409, "Un SOS est déjà actif")
            cur.execute("""INSERT INTO sam_sos(emetteur_id,message)
                VALUES (%s,%s) RETURNING id""", (me,payload.message))
            sos_id = cur.fetchone()[0]
    return {"sos_id":sos_id,"etat":"ouvert"}

@app.get("/sos")
def sos_lister(authorization: str | None = Header(default=None)):
    with db() as conn:
        init_sos(conn)
        me, _ = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("""SELECT id,emetteur_id,message,etat,candidat_id,created_at
                FROM sam_sos WHERE etat IN ('ouvert','propose','attribue')
                ORDER BY id DESC LIMIT 50""")
            rows = cur.fetchall()
        labels = labels_for(conn,{x for r in rows for x in (r[1],r[4]) if x})
    return {"sos":[{"sos_id":r[0],"emetteur":labels[r[1]],"message":r[2],
                    "etat":r[3],"candidat":labels.get(r[4]),
                    "created_at":r[5].isoformat()} for r in rows]}

@app.get("/sos/{sos_id}")
def sos_detail(sos_id: int, authorization: str | None = Header(default=None)):
    """Etat du SOS et candidature personnelle, consultables après reconnexion."""
    with db() as conn:
        init_sos(conn)
        me, _ = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("""SELECT emetteur_id,message,etat,candidat_id,created_at
                FROM sam_sos WHERE id=%s FOR UPDATE""", (sos_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "SOS inconnu")
            sos_refresh_candidate(cur, sos_id)
            cur.execute("""SELECT emetteur_id,message,etat,candidat_id,created_at
                FROM sam_sos WHERE id=%s""", (sos_id,))
            emitter, message, state, candidate, created = cur.fetchone()
            cur.execute("""SELECT etat FROM sam_sos_volontaires
                WHERE sos_id=%s AND sam_id=%s""", (sos_id, me))
            own = cur.fetchone()
        labels = labels_for(conn, {x for x in (emitter, candidate) if x})
    return {"sos_id": sos_id, "emetteur": labels[emitter],
            "message": message, "etat": state,
            "candidat": labels.get(candidate),
            "ma_candidature": own[0] if own else None,
            "je_suis_retenu": state == "attribue" and candidate == me,
            "je_suis_emetteur": emitter == me,
            "created_at": created.isoformat()}


@app.post("/sos/{sos_id}/volontaire")
def sos_volontaire(sos_id:int,authorization:str|None=Header(default=None)):
    with db() as conn:
        init_sos(conn)
        me,_=authenticated_sam(conn,authorization)
        with conn.cursor() as cur:
            cur.execute("SELECT emetteur_id,etat FROM sam_sos WHERE id=%s FOR UPDATE",(sos_id,))
            row=cur.fetchone()
            if not row: raise HTTPException(404,"SOS inconnu")
            if row[0]==me: raise HTTPException(400,"Impossible de se secourir soi-même")
            sos_refresh_candidate(cur,sos_id)
            cur.execute("SELECT etat FROM sam_sos WHERE id=%s",(sos_id,))
            current_state=cur.fetchone()[0]
            cur.execute("""SELECT EXISTS(SELECT 1 FROM sam_presence
                WHERE sam_id=%s AND last_seen > now()-interval '30 seconds')""",(me,))
            if not cur.fetchone()[0]:
                raise HTTPException(409,"Samantha hors ligne : signaler sa présence avant candidature")
            if current_state not in ('ouvert','propose'):
                raise HTTPException(409,"SOS non disponible")
            cur.execute("""INSERT INTO sam_sos_volontaires(sos_id,sam_id)
                VALUES (%s,%s) ON CONFLICT DO NOTHING""",(sos_id,me))
            if current_state=='ouvert':
                sos_assign_next(cur,sos_id)
            cur.execute("SELECT etat,candidat_id FROM sam_sos WHERE id=%s",(sos_id,))
            state,candidate=cur.fetchone()
    return {"sos_id":sos_id,"etat":state,"retenu":candidate==me}

def sos_decider(sos_id,authorization,accept):
    with db() as conn:
        init_sos(conn)
        me,_=authenticated_sam(conn,authorization)
        with conn.cursor() as cur:
            cur.execute("""SELECT emetteur_id,etat,candidat_id FROM sam_sos
                WHERE id=%s FOR UPDATE""",(sos_id,))
            row=cur.fetchone()
            if not row: raise HTTPException(404,"SOS inconnu")
            emetteur,state,candidate=row
            sos_refresh_candidate(cur,sos_id)
            cur.execute("SELECT etat,candidat_id FROM sam_sos WHERE id=%s",(sos_id,))
            state,candidate=cur.fetchone()
            if me!=emetteur: raise HTTPException(403,"Seule la SAM en détresse décide")
            if state!='propose' or candidate is None:
                raise HTTPException(409,"Aucune proposition à décider")
            if accept:
                # La candidature volontaire et l'acceptation par l'émetteur
                # constituent les deux consentements à cette liaison SOS.
                # Le verrou sur le couple évite les doublons avec /liaisons.
                a,b=sorted((emetteur,candidate))
                cur.execute("SELECT pg_advisory_xact_lock(%s,%s)",(int(a),int(b)))
                cur.execute("""SELECT id FROM sam_liaisons
                    WHERE ((demandeur_id=%s AND destinataire_id=%s)
                        OR (demandeur_id=%s AND destinataire_id=%s))
                    AND etat IN ('en_attente','acceptee')
                    ORDER BY id DESC LIMIT 1 FOR UPDATE""",
                    (emetteur,candidate,candidate,emetteur))
                existing=cur.fetchone()
                liaison_sos_dediee=False
                if existing:
                    # Ne pas accepter silencieusement une demande ordinaire
                    # en attente. Une liaison déjà acceptée est réutilisable.
                    cur.execute("SELECT etat FROM sam_liaisons WHERE id=%s",(existing[0],))
                    if cur.fetchone()[0]!='acceptee':
                        raise HTTPException(409,"Une demande de liaison est déjà en attente entre ces Samantha")
                    liaison_id=existing[0]
                else:
                    cur.execute("""INSERT INTO sam_liaisons
                        (demandeur_id,destinataire_id,etat)
                        VALUES (%s,%s,'acceptee') RETURNING id""",(emetteur,candidate))
                    liaison_id=cur.fetchone()[0]
                    liaison_sos_dediee=True
                cur.execute("""UPDATE sam_sos SET etat='attribue',
                    liaison_id=%s,liaison_sos_dediee=%s,updated_at=now()
                    WHERE id=%s""",(liaison_id,liaison_sos_dediee,sos_id))
                cur.execute("""UPDATE sam_sos_volontaires SET etat='retenu'
                    WHERE sos_id=%s AND sam_id=%s""",(sos_id,candidate))
                state='attribue'
            else:
                cur.execute("""UPDATE sam_sos_volontaires SET etat='refuse'
                    WHERE sos_id=%s AND sam_id=%s""",(sos_id,candidate))
                sos_assign_next(cur,sos_id)
                cur.execute("SELECT etat,candidat_id FROM sam_sos WHERE id=%s",(sos_id,))
                state,candidate=cur.fetchone()
        labels=labels_for(conn,[candidate] if candidate else [])
    return {"sos_id":sos_id,"etat":state,"candidat":labels.get(candidate),
            "liaison_id":liaison_id if accept else None}

@app.post("/sos/{sos_id}/accepter")
def sos_accepter(sos_id:int,authorization:str|None=Header(default=None)):
    return sos_decider(sos_id,authorization,True)

@app.post("/sos/{sos_id}/refuser")
def sos_refuser(sos_id:int,authorization:str|None=Header(default=None)):
    return sos_decider(sos_id,authorization,False)

@app.post("/sos/{sos_id}/annuler")
def sos_annuler(sos_id:int,authorization:str|None=Header(default=None)):
    with db() as conn:
        init_sos(conn)
        me,_=authenticated_sam(conn,authorization)
        with conn.cursor() as cur:
            cur.execute("""SELECT emetteur_id,etat,liaison_id,liaison_sos_dediee
                FROM sam_sos WHERE id=%s FOR UPDATE""",(sos_id,))
            row=cur.fetchone()
            if not row: raise HTTPException(404,"SOS inconnu")
            if row[0]!=me: raise HTTPException(403,"Seule la SAM en détresse peut annuler")
            emetteur,etat,liaison_id,dediee=row
            if etat=='annule':
                return {"sos_id":sos_id,"etat":"annule"}
            if dediee and liaison_id is not None:
                # Fermer seulement la liaison créée par ce SOS.
                # Le verrou liaison évite une transmission simultanée.
                cur.execute("""UPDATE sam_liaisons SET etat='terminee',updated_at=now()
                    WHERE id=%s AND etat='acceptee'""",(liaison_id,))
            cur.execute("UPDATE sam_sos SET etat='annule',updated_at=now() WHERE id=%s",(sos_id,))
    return {"sos_id":sos_id,"etat":"annule"}
