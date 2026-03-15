from urllib.parse import urlparse

from app.db.neo4j import driver
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment
from neo4j.exceptions import Neo4jError
from sqlalchemy.orm import Session


class GraphBuilder:
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
    # Indicator → Entity relationship
    # ------------------------------------------------

    def link_indicator_to_entity(self, indicator: Indicator):
        label = self._get_label(indicator.type)

        query = f"""
        MERGE (ind:Indicator {{value:$indicator}})
        MERGE (e:{label} {{value:$value}})
        MERGE (ind)-[:INDICATES]->(e)
        """

        with self.driver.session() as session:
            session.run(
                query,
                indicator=indicator.value,
                value=indicator.value,
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
    # Domain Infrastructure
    # ------------------------------------------------

    def create_domain_infrastructure_relationship(
        self,
        domain: str,
        enrichment: IndicatorEnrichment,
    ):
        query = """
        MATCH (d:Domain {value:$domain})

        FOREACH (_ IN CASE WHEN $asn IS NOT NULL THEN [1] ELSE [] END |
            MERGE (asn:ASN {value:$asn})
            MERGE (d)-[:RESOLVES_TO_ASN]->(asn)
        )

        FOREACH (_ IN CASE WHEN $hosting_provider IS NOT NULL THEN [1] ELSE [] END |
            MERGE (hp:HostingProvider {name:$hosting_provider})
            MERGE (d)-[:HOSTED_BY]->(hp)
        )

        FOREACH (_ IN CASE WHEN $registrar IS NOT NULL THEN [1] ELSE [] END |
            MERGE (r:Registrar {name:$registrar})
            MERGE (d)-[:REGISTERED_WITH]->(r)
        )
        """

        with self.driver.session() as session:
            session.run(
                query,
                domain=domain,
                asn=enrichment.asn,
                registrar=enrichment.registrar,
                hosting_provider=enrichment.hosting_provider,
            )

        if enrichment.nameservers:
            for ns in enrichment.nameservers.split(","):
                ns = ns.strip()

                if not ns:
                    continue

                query = """
                MATCH (d:Domain {value:$domain})
                MERGE (ns:Nameserver {value:$nameserver})
                MERGE (d)-[:USES_NS]->(ns)
                """

                with self.driver.session() as session:
                    session.run(query, domain=domain, nameserver=ns)

    # ------------------------------------------------
    # Domain → IP Pivot
    # ------------------------------------------------

    def create_domain_ip_relationship(self, domain: str, ip: str):
        query = """
        MERGE (d:Domain {value:$domain})
        MERGE (ip:IP {value:$ip})
        MERGE (d)-[:RESOLVES_TO_IP]->(ip)
        """

        with self.driver.session() as session:
            session.run(query, domain=domain, ip=ip)

    # ------------------------------------------------
    # Main Ingestion
    # ------------------------------------------------

    def ingest_indicator(
        self,
        indicator: Indicator,
        enrichment: IndicatorEnrichment | None,
    ):
        try:
            self.create_indicator_node(indicator)

            self.link_indicator_to_entity(indicator)

            indicator_type = indicator.type.lower()

            if indicator_type == "url":
                self.create_url_domain_relationship(indicator.value)

            if indicator_type == "domain" and enrichment:
                if (
                    enrichment.asn
                    or enrichment.registrar
                    or enrichment.hosting_provider
                    or enrichment.nameservers
                ):
                    self.create_domain_infrastructure_relationship(
                        indicator.value,
                        enrichment,
                    )

                # NEW: build Domain -> IP pivots from persisted enrichment
                if enrichment.resolved_ips:
                    for ip in enrichment.resolved_ips.split(","):
                        ip = ip.strip()

                        if not ip:
                            continue

                        self.create_domain_ip_relationship(indicator.value, ip)

            # NEW: support URL-based enrichments too, without changing prior logic
            if indicator_type == "url" and enrichment:
                parsed = urlparse(indicator.value)

                if parsed.netloc:
                    domain = parsed.netloc.lower()

                    if (
                        enrichment.asn
                        or enrichment.registrar
                        or enrichment.hosting_provider
                        or enrichment.nameservers
                    ):
                        self.create_domain_infrastructure_relationship(
                            domain,
                            enrichment,
                        )

                    if enrichment.resolved_ips:
                        for ip in enrichment.resolved_ips.split(","):
                            ip = ip.strip()

                            if not ip:
                                continue

                            self.create_domain_ip_relationship(domain, ip)

            # if indicator itself is IP, ensure node exists
            if indicator_type == "ip":
                query = """
                MERGE (ip:IP {value:$ip})
                """

                with self.driver.session() as session:
                    session.run(query, ip=indicator.value)

        except Neo4jError as e:
            raise RuntimeError(f"Neo4j graph ingestion failed: {e}")

    # ------------------------------------------------
    # Batch Build
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
