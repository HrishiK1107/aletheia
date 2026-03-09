from urllib.parse import urlparse

from app.db.neo4j import driver
from app.ingestion.enrichment.models.indicator_models import Indicator
from neo4j.exceptions import Neo4jError
from sqlalchemy.orm import Session


class GraphBuilder:
    """
    Responsible for inserting indicators into Neo4j as graph nodes
    and extracting deterministic relationships between them.
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

    def create_indicator_node(self, indicator: Indicator):
        label = self._get_label(indicator.type)

        query = f"""
        MERGE (i:{label} {{value: $value}})
        SET
            i.type = $type,
            i.source = $source,
            i.confidence = $confidence
        """

        with self.driver.session() as session:
            session.run(
                query,
                value=indicator.value,
                type=indicator.type,
                source=indicator.source,
                confidence=indicator.confidence,
            )

    def create_url_domain_relationship(self, url_value: str):
        """
        Extract domain from URL and create relationship:
        (URL)-[:HOSTS]->(Domain)
        """

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

    def ingest_indicator(self, indicator: Indicator):
        """
        Insert indicator node and extract relationships.
        """

        try:
            self.create_indicator_node(indicator)

            if indicator.type.lower() == "url":
                self.create_url_domain_relationship(indicator.value)

        except Neo4jError as e:
            raise RuntimeError(f"Neo4j graph ingestion failed: {e}")

    def ingest_all_indicators(self, db: Session):
        indicators = db.query(Indicator).all()

        for indicator in indicators:
            self.ingest_indicator(indicator)
