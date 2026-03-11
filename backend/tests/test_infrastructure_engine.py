from app.correlation.infrastructure_engine import InfrastructureEngine


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
