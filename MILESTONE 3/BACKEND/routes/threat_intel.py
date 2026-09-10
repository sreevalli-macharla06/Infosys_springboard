from fastapi import APIRouter, Query
from typing import Optional

from services.data_store import store
from models.schemas import ThreatIntelItem

router = APIRouter()


@router.get("/threat-intel", response_model=list[ThreatIntelItem])
def get_threat_intel(
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
):
    """Feeds the frontend's Threat Intelligence page (IOC table), queried live from MongoDB."""
    df = store.query_threat_intel(severity=severity, limit=limit)
    if df.empty:
        return []
    return [ThreatIntelItem(**row.to_dict()) for _, row in df.iterrows()]
