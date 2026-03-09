from app.db.neo4j import driver
from app.ingestion.enrichment.models.indicator_models import Indicator
from neo4j.exceptions import Neo4jError
from sqlalchemy.orm import Session


class GraphBuilder:
    """
    Responsible for inserting indicators into Neo4j as graph nodes.
    Uses deterministic MERGE queries to avoid duplicates.
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
        """
        Map indicator type to graph label.
        """
        return self.LABEL_MAP.get(indicator_type.lower(), "Indicator")

    def create_indicator_node(self, indicator: Indicator):
        """
        Insert a single indicator node into Neo4j.
        """

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

    def ingest_indicator(self, indicator: Indicator):
        """
        Public method to ingest a single indicator into graph.
        """
        try:
            self.create_indicator_node(indicator)
        except Neo4jError as e:
            raise RuntimeError(f"Neo4j graph ingestion failed: {e}")

    def ingest_all_indicators(self, db: Session):
        """
        Load all indicators from PostgreSQL and insert them into Neo4j.
        """

        indicators = db.query(Indicator).all()

        for indicator in indicators:
            self.ingest_indicator(indicator)
