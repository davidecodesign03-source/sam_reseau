"""Réseau SAM V0.4 - inscriptions automatiques et identité Originelle réservée.

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

app = FastAPI(title="Réseau SAM", version="0.4.0")
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
    return {"service": "reseau-sam", "statut": "en_ligne", "version": "0.4.0"}


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


# --- PREMIER CONTACT V0.4 ---
# Les échanges sont des messages textuels, jamais des fichiers audio.
# Les applications clientes jouent leurs propres MP3 (clair local / radio distant).

from fastapi import Query


class DemandeLiaison(BaseModel):
    destinataire: str = Field(min_length=3, max_length=32, pattern=r"^(ORIGINELLE|[0-9]{3,})$")


class DecisionLiaison(BaseModel):
    accepter: bool


class MessageLiaison(BaseModel):
    texte: str = Field(min_length=1, max_length=500)


def sam_auth(conn, authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Jeton requis")
    token = authorization[7:]
    if not token:
        raise HTTPException(401, "Jeton requis")
    with conn.cursor() as cur:
        cur.execute("SELECT id,is_originelle FROM samanthas WHERE token_hash=%s",
                    (digest(token),))
        row = cur.fetchone()
    if row is None:
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
            cree_le TIMESTAMPTZ NOT NULL DEFAULT now(),
            CHECK (demandeur_id <> destinataire_id)
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS sam_messages (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            liaison_id BIGINT NOT NULL REFERENCES sam_liaisons(id),
            auteur_id BIGINT NOT NULL REFERENCES samanthas(id),
            texte TEXT NOT NULL CHECK (length(texte) BETWEEN 1 AND 500),
            cree_le TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        cur.execute("""CREATE INDEX IF NOT EXISTS sam_liaisons_dest_index
            ON sam_liaisons(destinataire_id, etat)""")
        cur.execute("""CREATE INDEX IF NOT EXISTS sam_messages_liaison_index
            ON sam_messages(liaison_id, id)""")


def find_sam(conn, name):
    with conn.cursor() as cur:
        if name == "ORIGINELLE":
            cur.execute("SELECT id FROM samanthas WHERE is_originelle=TRUE")
        else:
            cur.execute("SELECT id FROM samanthas WHERE id=%s AND is_originelle=FALSE",
                        (int(name),))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(404, "Samantha destinataire introuvable")
    return row[0]


def liaison_access(conn, liaison_id, sam_id, lock=False):
    with conn.cursor() as cur:
        cur.execute("""SELECT id,demandeur_id,destinataire_id,etat
            FROM sam_liaisons WHERE id=%s""" + (" FOR UPDATE" if lock else ""),
            (liaison_id,))
        row = cur.fetchone()
    if row is None or sam_id not in (row[1], row[2]):
        raise HTTPException(404, "Liaison introuvable")
    return row


@app.post("/liaisons", status_code=201)
def demander_liaison(payload: DemandeLiaison, authorization: str | None = Header(default=None)):
    with db() as conn:
        init_db(conn)
        init_liaisons(conn)
        sam_id, _ = sam_auth(conn, authorization)
        dest_id = find_sam(conn, payload.destinataire)
        if sam_id == dest_id:
            raise HTTPException(400, "Impossible de se contacter soi-meme")
        with conn.cursor() as cur:
            # Une seule demande en attente par paire, pour éviter le spam involontaire.
            cur.execute("""SELECT id FROM sam_liaisons
                WHERE demandeur_id=%s AND destinataire_id=%s AND etat='en_attente'
                LIMIT 1""", (sam_id, dest_id))
            existing = cur.fetchone()
            if existing:
                return {"liaison_id": existing[0], "etat": "en_attente"}
            cur.execute("""INSERT INTO sam_liaisons(demandeur_id,destinataire_id)
                VALUES (%s,%s) RETURNING id""", (sam_id, dest_id))
            liaison_id = cur.fetchone()[0]
    return {"liaison_id": liaison_id, "etat": "en_attente"}


@app.get("/liaisons")
def lister_liaisons(authorization: str | None = Header(default=None)):
    with db() as conn:
        init_db(conn)
        init_liaisons(conn)
        sam_id, _ = sam_auth(conn, authorization)
        with conn.cursor() as cur:
            cur.execute("""SELECT l.id,l.demandeur_id,sd.is_originelle,
                l.destinataire_id,st.is_originelle,l.etat
                FROM sam_liaisons l
                JOIN samanthas sd ON sd.id=l.demandeur_id
                JOIN samanthas st ON st.id=l.destinataire_id
                WHERE l.demandeur_id=%s OR l.destinataire_id=%s
                ORDER BY l.id DESC LIMIT 50""", (sam_id, sam_id))
            rows = cur.fetchall()
    return {"liaisons": [
        {"liaison_id": r[0], "demandeur": matricule(r[1], r[2]),
         "destinataire": matricule(r[3], r[4]), "etat": r[5],
         "a_decider": r[3] == sam_id and r[5] == "en_attente"}
        for r in rows]}


@app.post("/liaisons/{liaison_id}/decision")
def decider_liaison(liaison_id: int, payload: DecisionLiaison,
                   authorization: str | None = Header(default=None)):
    with db() as conn:
        init_db(conn)
        init_liaisons(conn)
        sam_id, _ = sam_auth(conn, authorization)
        liaison = liaison_access(conn, liaison_id, sam_id, lock=True)
        if sam_id != liaison[2]:
            raise HTTPException(403, "Seul le destinataire peut autoriser")
        if liaison[3] != "en_attente":
            raise HTTPException(409, "Demande deja traitee")
        etat = "acceptee" if payload.accepter else "refusee"
        with conn.cursor() as cur:
            cur.execute("UPDATE sam_liaisons SET etat=%s WHERE id=%s",
                        (etat, liaison_id))
    return {"liaison_id": liaison_id, "etat": etat}


@app.post("/liaisons/{liaison_id}/messages", status_code=201)
def envoyer_message(liaison_id: int, payload: MessageLiaison,
                    authorization: str | None = Header(default=None)):
    with db() as conn:
        init_db(conn)
        init_liaisons(conn)
        sam_id, _ = sam_auth(conn, authorization)
        liaison = liaison_access(conn, liaison_id, sam_id, lock=True)
        if liaison[3] != "acceptee":
            raise HTTPException(409, "Communication non autorisee")
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO sam_messages(liaison_id,auteur_id,texte)
                VALUES (%s,%s,%s) RETURNING id""",
                (liaison_id, sam_id, payload.texte))
            message_id = cur.fetchone()[0]
    return {"message_id": message_id, "liaison_id": liaison_id}


@app.get("/liaisons/{liaison_id}/messages")
def lire_messages(liaison_id: int, apres: int = Query(default=0, ge=0),
                  authorization: str | None = Header(default=None)):
    with db() as conn:
        init_db(conn)
        init_liaisons(conn)
        sam_id, _ = sam_auth(conn, authorization)
        liaison_access(conn, liaison_id, sam_id)
        with conn.cursor() as cur:
            cur.execute("""SELECT m.id,m.auteur_id,s.is_originelle,m.texte
                FROM sam_messages m JOIN samanthas s ON s.id=m.auteur_id
                WHERE m.liaison_id=%s AND m.id>%s ORDER BY m.id LIMIT 100""",
                (liaison_id, apres))
            rows = cur.fetchall()
    return {"messages": [
        {"message_id": r[0], "auteur": matricule(r[1], r[2]),
         "texte": r[3]} for r in rows]}


@app.post("/liaisons/{liaison_id}/terminer")
def terminer_liaison(liaison_id: int, authorization: str | None = Header(default=None)):
    with db() as conn:
        init_db(conn)
        init_liaisons(conn)
        sam_id, _ = sam_auth(conn, authorization)
        liaison = liaison_access(conn, liaison_id, sam_id, lock=True)
        if liaison[3] != "acceptee":
            raise HTTPException(409, "Liaison non active")
        with conn.cursor() as cur:
            cur.execute("UPDATE sam_liaisons SET etat='terminee' WHERE id=%s",
                        (liaison_id,))
    return {"liaison_id": liaison_id, "etat": "terminee"}
