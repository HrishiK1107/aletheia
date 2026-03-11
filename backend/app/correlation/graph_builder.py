from urllib.parse import urlparse

from app.db.neo4j import driver
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment
from neo4j.exceptions import Neo4jError
from sqlalchemy.orm import Session


class GraphBuilder:
    """
    Responsible for inserting indicators into Neo4j
    and building deterministic infrastructure relationships.
    """

    LABEL_MAP = {
        "domain": "Domain",
        "ip": "IP",
        "url": "URL",
        "hash": "Hash",
    }

    def __init__(self):
        self.driver = driver

    def _get_label(self, indicator_type: str) -> str:
        return self.LABEL_MAP.get(indicator_type.lower(), "Indicator")

    # ------------------------------------------------
    # Indicator Node
    # ------------------------------------------------

    def create_indicator_node(self, indicator: Indicator):

        label = self._get_label(indicator.type)

        query = f"""
        MERGE (i:{label} {{value:$value}})
        SET
            i.type=$type,
            i.source=$source,
            i.confidence=$confidence
        """

        with self.driver.session() as session:
            session.run(
                query,
                value=indicator.value,
                type=indicator.type,
                source=indicator.source,
                confidence=indicator.confidence,
            )

    # ------------------------------------------------
    # URL → Domain
    # ------------------------------------------------

    def create_url_domain_relationship(self, url_value: str):

        parsed = urlparse(url_value)

        if not parsed.netloc:
            return

        domain = parsed.netloc.lower()

        query = """
        MERGE (u:URL {value:$url})
        MERGE (d:Domain {value:$domain})
        MERGE (u)-[:HOSTS]->(d)
        """

        with self.driver.session() as session:
            session.run(query, url=url_value, domain=domain)

    # ------------------------------------------------
    # Domain → IP
    # ------------------------------------------------

    def create_domain_ip_relationship(self, domain: str, ip: str):

        query = """
        MERGE (d:Domain {value:$domain})
        MERGE (ip:IP {value:$ip})
        MERGE (d)-[:RESOLVES_TO]->(ip)
        """

        with self.driver.session() as session:
            session.run(query, domain=domain, ip=ip)

    # ------------------------------------------------
    # Infrastructure Node
    # ------------------------------------------------

    def create_infrastructure_node(self, enrichment: IndicatorEnrichment):

        query = """
        MERGE (infra:Infrastructure {
            asn:$asn,
            registrar:$registrar,
            hosting_provider:$hosting_provider,
            nameservers:$nameservers
        })
        """

        with self.driver.session() as session:
            session.run(
                query,
                asn=enrichment.asn,
                registrar=enrichment.registrar,
                hosting_provider=enrichment.hosting_provider,
                nameservers=enrichment.nameservers,
            )

    # ------------------------------------------------
    # Domain → Infrastructure
    # ------------------------------------------------

    def create_domain_infrastructure_relationship(self, domain, enrichment):

        query = """
        MATCH (d:Domain {value:$domain})
        MERGE (infra:Infrastructure {
            asn:$asn,
            registrar:$registrar,
            hosting_provider:$hosting_provider,
            nameservers:$nameservers
        })
        MERGE (d)-[:PART_OF_INFRA]->(infra)
        """

        with self.driver.session() as session:
            session.run(
                query,
                domain=domain,
                asn=enrichment.asn,
                registrar=enrichment.registrar,
                hosting_provider=enrichment.hosting_provider,
                nameservers=enrichment.nameservers,
            )

    # ------------------------------------------------
    # Main Ingestion Logic
    # ------------------------------------------------

    def ingest_indicator(self, indicator: Indicator, enrichment: IndicatorEnrichment | None):

        try:

            self.create_indicator_node(indicator)

            if indicator.type.lower() == "url":
                self.create_url_domain_relationship(indicator.value)

            if indicator.type.lower() == "domain" and enrichment:

                if enrichment.nameservers:
                    self.create_domain_infrastructure_relationship(indicator.value, enrichment)

        except Neo4jError as e:
            raise RuntimeError(f"Neo4j graph ingestion failed: {e}")

    # ------------------------------------------------
    # Batch Graph Build
    # ------------------------------------------------

    def ingest_all_indicators(self, db: Session):

        indicators = db.query(Indicator).all()

        for indicator in indicators:

            enrichment = (
                db.query(IndicatorEnrichment)
                .filter(IndicatorEnrichment.indicator_id == indicator.id)
                .first()
            )

            self.ingest_indicator(indicator, enrichment)
