"""Réseau SAM V0.2 : enregistrement sécurisé et matricules persistants.

Prérequis : DATABASE_URL (PostgreSQL) et SAM_ENROLLMENT_KEY (secret fort).
Aucune identité n'est enregistrée dans le disque éphémère de Render.
"""
import hashlib
import hmac
import os
import secrets
from contextlib import contextmanager

import psycopg
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="Réseau SAM", version="0.2.0")


def _database_url():
    value = os.getenv("DATABASE_URL", "")
    if not value:
        raise HTTPException(503, "Base de données non configurée")
    return value


@contextmanager
def db():
    try:
        with psycopg.connect(_database_url()) as conn:
            yield conn
    except psycopg.OperationalError:
        raise HTTPException(503, "Base de données momentanément indisponible") from None


def init_db(conn):
    with conn.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS samanthas (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            installation_id TEXT NOT NULL UNIQUE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Inscription(BaseModel):
    installation_id: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


@app.get("/")
def accueil():
    return {"service": "reseau-sam", "statut": "en_ligne", "version": "0.2.0"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def inscrire(payload: Inscription, x_sam_enrollment_key: str | None = Header(default=None)):
    secret = os.getenv("SAM_ENROLLMENT_KEY", "")
    if not secret:
        raise HTTPException(503, "Inscriptions non configurées")
    if not x_sam_enrollment_key or not hmac.compare_digest(x_sam_enrollment_key, secret):
        raise HTTPException(403, "Clé d'inscription invalide")

    token = secrets.token_urlsafe(32)
    with db() as conn:
        init_db(conn)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO samanthas (installation_id, token_hash)
                VALUES (%s, %s)
                ON CONFLICT (installation_id) DO NOTHING
                RETURNING id
            """, (payload.installation_id, token_digest(token)))
            row = cur.fetchone()
            if row is None:
                raise HTTPException(409, "Cette installation est déjà enregistrée")
            matricule = f"{row[0]:03d}"
    return {"matricule": matricule, "token": token, "message": "Conservez le token en lieu sûr : il n'est affiché qu'une fois."}


@app.get("/me")
def moi(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Token requis")
    token = authorization[7:]
    if not token:
        raise HTTPException(401, "Token requis")
    with db() as conn:
        init_db(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM samanthas WHERE token_hash = %s", (token_digest(token),))
            row = cur.fetchone()
    if row is None:
        raise HTTPException(401, "Token invalide")
    return {"matricule": f"{row[0]:03d}", "connecte": True}
