from app.db.neo4j import driver


class CampaignDetector:
    """
    Detect campaign candidate clusters using graph connectivity.
    """

    def __init__(self):
        self.driver = driver

    def find_connected_clusters(self):
        """
        Identify clusters of related indicators using graph traversal.

        A cluster is a connected group of nodes.
        """

        query = """
        MATCH (n)
        WHERE n:URL OR n:Domain OR n:IP OR n:Hash
        WITH collect(n) AS nodes
        UNWIND nodes AS node
        MATCH path=(node)-[*]-(connected)
        WHERE connected:URL OR connected:Domain OR connected:IP OR connected:Hash
        RETURN node.value AS root,
               collect(DISTINCT connected.value) AS cluster
        """

        with self.driver.session() as session:
            result = session.run(query)

            clusters = []

            for record in result:
                cluster = record["cluster"]

                if len(cluster) > 1:
                    clusters.append(cluster)

            return clusters

    def detect_campaign_candidates(self):
        """
        Wrapper used by correlation engine.
        """

        clusters = self.find_connected_clusters()

        campaigns = []

        for i, cluster in enumerate(clusters):
            campaigns.append(
                {
                    "campaign_id": f"candidate_{i+1}",
                    "indicators": cluster,
                    "size": len(cluster),
                }
            )

        return campaigns
