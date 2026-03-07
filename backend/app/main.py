from app.core.logging import get_logger, setup_logging
from fastapi import FastAPI

setup_logging()

logger = get_logger(__name__)

app = FastAPI(title="Aletheia")


@app.get("/health")
def health():
    logger.info("Health check requested")
    return {"status": "ok"}
