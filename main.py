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

app = FastAPI(title="Réseau SAM", version="0.7.0")
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

# --- V0.8 (préparation) : informations partagées uniquement entre contacts autorisés ---
# Les préférences de confidentialité sont transmises par le client et
# les données non autorisées sont effacées côté serveur.
from typing import Optional

class SamSharedStatus(BaseModel):
    ship_model: Optional[str] = Field(default=None, max_length=100)
    system: Optional[str] = Field(default=None, max_length=160)
    fuel: Optional[float] = Field(default=None, ge=0, le=100000)
    share_ship_model: bool = False
    share_system: bool = False
    share_fuel: bool = False

def init_shared_status(conn):
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_shared_status (
            sam_id BIGINT PRIMARY KEY REFERENCES samanthas(id) ON DELETE CASCADE,
            ship_model TEXT, system TEXT, fuel DOUBLE PRECISION,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")

@app.post("/shared-status")
def publish_shared_status(payload: SamSharedStatus,
                          authorization: str | None = Header(default=None)):
    with db() as conn:
        init_shared_status(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO sam_shared_status(sam_id,ship_model,system,fuel,updated_at)
                VALUES (%s,%s,%s,%s,now()) ON CONFLICT(sam_id) DO UPDATE SET
                ship_model=excluded.ship_model,system=excluded.system,
                fuel=excluded.fuel,updated_at=now()""",
                (me_id, payload.ship_model if payload.share_ship_model else None,
                 payload.system if payload.share_system else None,
                 payload.fuel if payload.share_fuel else None))
    return {"ok": True}

@app.get("/shared-status/{target}")
def read_shared_status(target: str,
                       authorization: str | None = Header(default=None)):
    with db() as conn:
        init_shared_status(conn)
        init_liaisons(conn)
        me_id, _ = authenticated_sam(conn, authorization)
        target_id = find_sam(conn, target)
        with conn.cursor() as cur:
            cur.execute("""SELECT EXISTS(
                SELECT 1 FROM sam_liaisons WHERE etat='acceptee'
                AND ((demandeur_id=%s AND destinataire_id=%s)
                  OR (demandeur_id=%s AND destinataire_id=%s)))""",
                (me_id,target_id,target_id,me_id))
            if not cur.fetchone()[0]:
                raise HTTPException(403, "Liaison acceptée requise")
            cur.execute("""SELECT ship_model,system,fuel,updated_at
                FROM sam_shared_status WHERE sam_id=%s
                AND updated_at>now()-interval '10 minutes'""", (target_id,))
            row=cur.fetchone()
    return {"matricule":target,"ship_model":row[0] if row else None,
            "system":row[1] if row else None,"fuel":row[2] if row else None}
