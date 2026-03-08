from app.ingestion.collectors.collector_runner import run_collectors
from fastapi import APIRouter

router = APIRouter(prefix="/feeds", tags=["feeds"])


@router.get("/collect")
def collect_feeds():

    indicators = run_collectors()

    return {
        "collected": len(indicators),
        "sample": indicators[:10],
    }
