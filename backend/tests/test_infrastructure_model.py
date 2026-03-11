from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment


def test_indicator_enrichment_model():

    e = IndicatorEnrichment(
        indicator_id=1,
        asn="AS13335",
        registrar="Namecheap",
        hosting_provider="Cloudflare",
        nameservers="ns1.cloudflare.com,ns2.cloudflare.com",
        ssl_fingerprint="ABC123",
    )

    assert e.indicator_id == 1
    assert e.asn == "AS13335"
    assert e.registrar == "Namecheap"
