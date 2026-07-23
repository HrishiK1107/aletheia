from app.correlation.infrastructure_engine import InfrastructureEngine
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment


def test_similarity():

    engine = InfrastructureEngine()

    f1 = {"asn:AS13335", "registrar:Namecheap", "ns:ns1.cloudflare.com"}
    f2 = {"asn:AS13335", "registrar:Namecheap", "ns:ns1.cloudflare.com"}

    score = engine.similarity(f1, f2)

    assert score == 1.0


def test_similarity_partial():

    engine = InfrastructureEngine()

    f1 = {"asn:AS13335", "registrar:Namecheap"}
    f2 = {"asn:AS13335", "hosting:Cloudflare"}

    score = engine.similarity(f1, f2)

    assert score > 0


def test_weighted_fingerprint_prefers_hosting_provider_over_asn():
    """
    CONTEXT.md item 2.1: hosting_provider and asn are collinear (same
    company, two fields). weighted_fingerprint() must emit exactly one
    "org:" feature, not both -- otherwise one fact is double-counted as
    two pieces of corroborating evidence.
    """
    engine = InfrastructureEngine()

    enrichment = IndicatorEnrichment(asn="AS13335", hosting_provider="Cloudflare, Inc.")

    features = engine.weighted_fingerprint(enrichment)

    assert features == {"org:Cloudflare, Inc."}


def test_weighted_fingerprint_falls_back_to_asn():
    """No hosting_provider resolved -> asn is the only identity signal available."""
    engine = InfrastructureEngine()

    enrichment = IndicatorEnrichment(asn="AS13335", hosting_provider=None)

    features = engine.weighted_fingerprint(enrichment)

    assert features == {"org:AS13335"}


def test_weighted_fingerprint_includes_resolved_ip():
    """
    resolved_ip is one of the four feature classes for item 6 (unlike the
    unmerged fingerprint() used by the Jaccard baseline, which never
    includes it).
    """
    engine = InfrastructureEngine()

    enrichment = IndicatorEnrichment(
        hosting_provider="Vercel",
        registrar="Namecheap",
        nameservers="ns1.example.com,ns2.example.com",
        resolved_ips="1.2.3.4,5.6.7.8",
    )

    features = engine.weighted_fingerprint(enrichment)

    assert features == {
        "org:Vercel",
        "registrar:Namecheap",
        "ns:ns1.example.com",
        "ns:ns2.example.com",
        "ip:1.2.3.4",
        "ip:5.6.7.8",
    }


def test_compute_feature_degrees():
    engine = InfrastructureEngine()

    fingerprints = {
        "a.com": {"org:Cloudflare, Inc.", "registrar:GoDaddy"},
        "b.com": {"org:Cloudflare, Inc.", "registrar:Namecheap"},
        "c.com": {"org:Cloudflare, Inc."},
        "d.com": {"registrar:GoDaddy"},
    }

    degrees = engine.compute_feature_degrees(fingerprints)

    assert degrees["org:Cloudflare, Inc."] == 3
    assert degrees["registrar:GoDaddy"] == 2
    assert degrees["registrar:Namecheap"] == 1
