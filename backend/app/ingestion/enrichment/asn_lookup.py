import datetime
import logging
from pathlib import Path

import geoip2.database
import geoip2.errors
from app.core.config import settings

logger = logging.getLogger(__name__)

# backend/app/ingestion/enrichment/asn_lookup.py -> repo root is 4 levels up.
# Resolved this way (not relative to process cwd) so it works the same
# whether invoked via uvicorn (cwd=backend/), a worker script, pytest, or
# an ad-hoc script from the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[4]


def _resolve_db_path() -> Path:
    path = Path(settings.geolite2_asn_db_path)
    return path if path.is_absolute() else _REPO_ROOT / path


_DB_PATH = _resolve_db_path()

if not _DB_PATH.exists():
    raise RuntimeError(
        f"GeoLite2 ASN database not found at {_DB_PATH} "
        f"(from settings.geolite2_asn_db_path={settings.geolite2_asn_db_path!r}). "
        "ASN enrichment requires this file and has no network fallback -- "
        "CONTEXT.md item 2.7: the previous network-based lookup (ip-api.com) "
        "silently collapsed to 5.6% coverage once run under the concurrency "
        "item 2.6 introduced, indistinguishable from genuinely missing data. "
        "Download GeoLite2-ASN.mmdb (requires a free MaxMind account) and "
        "place it at this path before starting any process that imports "
        "this module."
    )

_reader = geoip2.database.Reader(str(_DB_PATH))
_metadata = _reader.metadata()

if _metadata.database_type != "GeoLite2-ASN":
    raise RuntimeError(
        f"{_DB_PATH} is a {_metadata.database_type!r} database, not "
        "GeoLite2-ASN -- check geolite2_asn_db_path points at the right file."
    )

_BUILD_DATE = datetime.datetime.fromtimestamp(_metadata.build_epoch, tz=datetime.timezone.utc)

logger.info(
    f"Loaded GeoLite2-ASN database from {_DB_PATH}, build date {_BUILD_DATE.isoformat()}"
)


def get_database_build_date() -> datetime.datetime:
    """
    The GeoLite2 snapshot's build date -- for run/results metadata, so
    ASN-derived results can cite the exact snapshot used (reproducibility
    is the reason this is a frozen local file rather than a live lookup;
    see CONTEXT.md item 2.7).
    """
    return _BUILD_DATE


def lookup_asn(ip: str) -> dict | None:
    """
    Resolve IP -> ASN + hosting provider from the local GeoLite2-ASN
    snapshot. No network call, no rate limit (CONTEXT.md item 2.7).

    Returns:
        {
            "asn": "AS13335",
            "hosting_provider": "Cloudflare, Inc."
        }
    """

    try:
        response = _reader.asn(ip)
    except geoip2.errors.AddressNotFoundError:
        # Genuinely not in the database (private/reserved/unallocated
        # ranges) -- a real "no ASN for this IP", not a lookup failure.
        return None
    except ValueError:
        # Malformed IP string.
        return None

    if response.autonomous_system_number is None:
        return None

    return {
        "asn": f"AS{response.autonomous_system_number}",
        "hosting_provider": response.autonomous_system_organization,
    }
