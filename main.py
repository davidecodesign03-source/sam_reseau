import os
from fastapi import FastAPI

app = FastAPI(title="Réseau SAM", version="0.1.0")

@app.get("/")
def accueil():
    return {"service": "reseau-sam", "statut": "en_ligne", "version": "0.1.0"}

@app.get("/health")
def health():
    return {"ok": True}
