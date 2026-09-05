from fastapi import APIRouter, Query
from typing import Optional

from services.data_store import store
from models.schemas import VulnerabilityItem

router = APIRouter()


@router.get("/vulnerabilities", response_model=list[VulnerabilityItem])
def get_vulnerabilities(
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
):
    """Feeds the frontend's Vulnerabilities page (CVE table), queried live from MongoDB."""
    df = store.query_vulnerabilities(severity=severity, limit=limit)
    if df.empty:
        return []
    return [VulnerabilityItem(**row.to_dict()) for _, row in df.iterrows()]
