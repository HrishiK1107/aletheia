from app.db.neo4j import driver


class CampaignDetector:
    """
    Detect campaign candidate clusters using graph connectivity.
    """

    def __init__(self):
        self.driver = driver

    def find_connected_clusters(self):
        """
        Identify clusters of related indicators using controlled graph traversal.

        Fix added:
        - limit traversal depth
        - restrict traversal to infrastructure-relevant relationships
        - deduplicate clusters
        """

        query = """
        MATCH (node)
        WHERE node:URL OR node:Domain OR node:IP OR node:Hash

        MATCH path=(node)-[:HOSTS|RESOLVES_TO_IP|RESOLVES_TO_ASN|HOSTED_BY|REGISTERED_WITH|USES_NS|INDICATES*1..4]-(connected)
        WHERE connected:URL OR connected:Domain OR connected:IP OR connected:Hash

        WITH node, collect(DISTINCT connected.value) + node.value AS raw_cluster
        UNWIND raw_cluster AS item
        WITH node, collect(DISTINCT item) AS cluster
        WHERE size(cluster) > 1

        RETURN DISTINCT cluster
        """

        with self.driver.session() as session:
            result = session.run(query)

            unique_clusters = set()
            clusters = []

            for record in result:
                cluster = sorted(record["cluster"])
                cluster_key = tuple(cluster)

                if cluster_key in unique_clusters:
                    continue

                unique_clusters.add(cluster_key)
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
