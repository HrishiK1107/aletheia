from unittest.mock import MagicMock, patch

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


def test_ip_port_with_invalid_host_left_unrecognized_not_rejected():
    """
    canonicalize_indicator_type only rewrites "ip:port" when the host
    actually is a valid IP (confirmed 977/977 in the real ThreatFox
    sample). A genuinely unparseable host is left as the unrecognized
    "ip:port" type -- same pass-through behaviour as before this fix
    (validate_indicator's unknown-type default), not a new rejection path.
    """

    db = MagicMock()

    indicator = IndicatorCreate(
        value="not-an-ip:notaport",
        type="ip:port",
        source="test",
        confidence=50,
    )

    result = create_indicator(db, indicator)

    assert result is not None


def test_ip_port_with_valid_host_canonicalizes_to_ip():
    db = MagicMock()

    indicator = IndicatorCreate(
        value="153.75.245.123:1224",
        type="ip:port",
        source="test",
        confidence=50,
    )

    with patch("app.services.indicator_service.find_duplicate", return_value=None):
        create_indicator(db, indicator)

    created = db.add.call_args_list[0].args[0]
    assert created.value == "153.75.245.123"
    assert created.type == "ip"
