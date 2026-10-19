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

app = FastAPI(title="Réseau SAM", version="0.3.0")
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
    return {"service": "reseau-sam", "statut": "en_ligne", "version": "0.3.0"}


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
