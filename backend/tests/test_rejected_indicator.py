from unittest.mock import MagicMock

from app.schemas.indicator_schema import IndicatorCreate
from app.services.indicator_service import create_indicator


def test_invalid_indicator_goes_to_rejected():

    db = MagicMock()

    indicator = IndicatorCreate(
        value="999.999.999.999",
        type="ip",
        source="test",
        confidence=50,
    )

    result = create_indicator(db, indicator)

    assert result is None
