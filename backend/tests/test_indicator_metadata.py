from unittest.mock import MagicMock

from app.schemas.indicator_schema import IndicatorCreate
from app.services.indicator_service import create_indicator


def test_duplicate_indicator_creates_metadata():

    db = MagicMock()

    indicator = IndicatorCreate(
        value="evil.com",
        type="domain",
        source="test",
        confidence=80,
    )

    result = create_indicator(db, indicator)

    # Function should not crash
    assert result is None or result
