# SentinelAI Security — Backend API

An enterprise-ready FastAPI backend for the AI-Assisted Threat Detection Dashboard (Milestone 1). It processes cybersecurity logs, maps events to MITRE ATT&CK techniques, and serves real-time security data powered by MongoDB.

## Features

- **FastAPI Framework:** High-performance async REST API with automatic interactive documentation.
- **MongoDB Integration:** Live querying layer serving as the single source of truth.
- **Automatic Database Initialization:** Auto-detects empty database on startup and seeds datasets seamlessly.
- **Threat Intelligence:** Enriches security logs with IOC indicators and confidence metrics.
- **MITRE ATT&CK Mapping:** Maps security event types directly to standardized MITRE techniques and tactics.
- **Feature Engineering:** Pre-calculates security risk indicators, temporal attributes, and event frequencies.
- **Live Dashboard Integration:** Connects directly with the React frontend for real-time monitoring.

## Tech Stack

- **Core:** Python 3.9+
- **API Framework:** FastAPI, Uvicorn
- **Database:** MongoDB, PyMongo
- **Data Processing:** Pandas, NumPy
- **Validation:** Pydantic

## Folder Structure

```
BACKEND/
├── data/           # Source CSV datasets
├── database/       # Connection manager & automatic seeder
├── models/         # Pydantic schemas
├── routes/         # FastAPI route handlers
├── services/       # MongoDB query layer & risk scoring
├── main.py         # FastAPI application instance
└── run.py          # Application entry point
```

## Prerequisites

Choose one of the two options below to run the backend.

### Option 1 (Recommended) — Docker

**Requirements:** Docker Desktop

Run the service:
```bash
docker compose up --build
```
For subsequent runs:
```bash
docker compose up
```

Docker automatically starts MongoDB, launches the FastAPI server, and initializes the database on first run.

### Option 2 — Local Development

**Requirements:** Python 3.9+, MongoDB (running on default port 27017)

Install dependencies and start the backend:
```bash
pip install -r requirements.txt
python run.py
```

Automatic database initialization also runs seamlessly in local mode.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/events` | GET | List security events with severity & type filtering |
| `/events` | POST | Ingest a new security event |
| `/stats` | GET | Overview KPI summary metrics |
| `/threats` | GET | Threat counts grouped by attack type |
| `/vulnerabilities` | GET | System vulnerability (CVE) reports |
| `/threat-intel` | GET | Threat intelligence IOC records |

Interactive FastAPI Swagger documentation is available at:  
**http://localhost:8000/docs**

## Project Structure

- **`data/`**: Datasets imported automatically into MongoDB during initial startup.
- **`database/`**: Handles database connection lifecycle (`mongo_db.py`) and idempotent auto-seeding (`seeder.py`).
- **`models/`**: Pydantic models enforcing strict validation for API requests and responses.
- **`routes/`**: Route definitions categorised by domain (`events`, `stats`, `threats`, `vulnerabilities`, `threat_intel`).
- **`services/`**: Query abstraction layer (`data_store.py`) fetching live MongoDB documents per request.

## Known Limitations

- **Authentication:** Endpoint authentication is not implemented (outside Milestone 1 scope).
- **Risk Scoring:** Uses a deterministic calculation for Milestone 1; ML-based predictive risk scoring will be integrated in Milestone 2.
