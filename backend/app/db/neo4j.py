from app.core.config import settings
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable

driver = GraphDatabase.driver(
    settings.neo4j_uri,
    auth=(settings.neo4j_user, settings.neo4j_password),
)


def check_neo4j():
    try:
        with driver.session() as session:
            session.run("RETURN 1")
        return True
    except (Neo4jError, ServiceUnavailable):
        return False
