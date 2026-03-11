from app.attribution.attribution_engine import AttributionEngine


def test_attribution():

    engine = AttributionEngine()

    campaign = {
        "campaign_id": "campaign_1",
        "indicators": ["login.evil.com"],
    }

    class Dummy:
        registrar = "Namecheap"
        asn = "AS13335"

    result = engine.attribute_campaign(campaign, Dummy())

    assert "actor" in result
