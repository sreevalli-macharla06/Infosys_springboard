"""
database/seeder.py

Auto-seeder called at startup.

Reuses the existing ``mongo`` connection (no second MongoClient is created).
Uses the project logger so all output goes through the same channel as the
rest of the startup sequence.

Public API
----------
seed_if_empty(db)
    Checks whether ``security_events`` has any documents.
    - If yes  → logs "already initialised" and returns immediately (no writes).
    - If no   → imports all 7 CSV datasets, creates indexes, logs progress.
    Raises RuntimeError on any failure so the calling lifespan can propagate
    the error and prevent a broken startup.
"""
import os
import pandas as pd
from pymongo import ASCENDING

from utils.logger import get_logger

log = get_logger("seeder")

# Absolute path to the data/ directory (one level above this file's package dir)
_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
)

# Ordered so dependencies (e.g. mitre_attack_mapping) are present before the
# main events collection is loaded.  The tuple is:
#   (csv_filename, [(index_field, direction), ...])
_COLLECTIONS = [
    ("mitre_attack_mapping",    "mitre_attack_mapping.csv",    [("event_type",       ASCENDING)]),
    ("mitre_technique_catalog", "mitre_technique_catalog.csv", [("mitre_id",         ASCENDING)]),
    ("assets",                  "assets.csv",                  [("asset_name",       ASCENDING)]),
    ("vulnerabilities",         "vulnerabilities.csv",         [("cve_id",           ASCENDING)]),
    ("threat_intelligence",     "threat_intelligence.csv",     [("indicator_value",  ASCENDING)]),
    ("incident_history",        "incident_history.csv",        [("event_id",         ASCENDING)]),
    # security_events last — it is the sentinel used to detect an empty DB
    ("security_events",         "security_events.csv",         [("event_id",         ASCENDING),
                                                                ("timestamp",        ASCENDING)]),
]


def seed_if_empty(db) -> None:
    """
    Idempotent seeder — safe to call on every startup.

    Parameters
    ----------
    db : pymongo.database.Database
        The already-connected ``threat_detection`` database object obtained
        from ``mongo.get_database()``.
    """
    # ── Guard: skip entirely if data already exists ───────────────────────────
    existing = db["security_events"].count_documents({})
    if existing > 0:
        log.info(f"Database already initialised ({existing:,} security events). Skipping import.")
        return

    # ── Fresh database: import all collections ────────────────────────────────
    log.info("Database is empty — importing datasets now...")

    for coll_name, csv_file, indexes in _COLLECTIONS:
        csv_path = os.path.join(_DATA_DIR, csv_file)

        if not os.path.exists(csv_path):
            raise RuntimeError(
                f"Dataset file not found: {csv_path}. "
                f"Make sure the data/ directory is present and intact."
            )

        # Read CSV and insert (collection is empty, so no delete_many needed)
        df = pd.read_csv(csv_path)
        records = df.to_dict("records")

        if not records:
            log.warning(f"  {csv_file} is empty — skipping.")
            continue

        db[coll_name].insert_many(records)
        log.info(f"  Imported {coll_name} ({len(records):,} records)")

        # Ensure indexes (create_index is idempotent)
        for field, direction in indexes:
            db[coll_name].create_index([(field, direction)])

    log.info("Initialization complete. All datasets loaded successfully.")
