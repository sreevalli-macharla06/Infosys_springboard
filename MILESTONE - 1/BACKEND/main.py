"""
AI-Assisted Threat Detection Dashboard — Backend API (Milestone 1)

Preferred start:
    python run.py

Alternative (manual uvicorn):
    uvicorn main:app --reload --port 8000

Interactive docs at http://localhost:8000/docs once running.
"""
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()  # picks up MONGO_URI etc. from .env if present

from services.data_store import store
from routes import events, stats, threats, threat_intel, vulnerabilities
from database.mongo_db import mongo
from database.seeder import seed_if_empty
from utils.logger import get_logger

log = get_logger("threat_dashboard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan handler — runs once at startup and once at shutdown."""
    # 1. Connect to MongoDB (raises RuntimeError with a clear message if unreachable)
    mongo.connect()

    # 2. Auto-seed: imports all datasets on first run; no-op on subsequent runs.
    #    seed_if_empty() raises RuntimeError on any failure, which prevents the
    #    server from completing startup with a broken/partial database.
    seed_if_empty(mongo.get_database())

    # 3. Cache the static MITRE mapping in memory (10 rows, never written to)
    store.load()

    yield

    # Shutdown: close the MongoDB connection
    mongo.disconnect()


app = FastAPI(
    title="Threat Detection Dashboard API",
    description="Backend for the AI-Assisted Threat Detection Dashboard — Milestone 1",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS: allows the React frontend (running on a different port, e.g. 5173) to call this API.
# Origins are configurable via CORS_ORIGINS (comma-separated) so you don't have to edit code
# to add your deployed frontend's URL — defaults cover the common local dev setups.
import os
default_origins = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", default_origins).split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(events.router, tags=["Events"])
app.include_router(stats.router, tags=["Stats"])
app.include_router(threats.router, tags=["Threats"])
app.include_router(threat_intel.router, tags=["Threat Intelligence"])
app.include_router(vulnerabilities.router, tags=["Vulnerabilities"])


@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "Threat Detection Dashboard API is running"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "data_loaded": store.loaded}
