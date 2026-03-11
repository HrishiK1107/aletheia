class TechniqueMapper:
    """
    Map indicators to MITRE ATT&CK techniques.
    """

    DOMAIN_TECHNIQUES = {
        "login": "T1566",
        "auth": "T1078",
        "update": "T1105",
    }

    URL_TECHNIQUES = {
        "phish": "T1566",
        "download": "T1105",
    }

    def map_domain(self, domain):

        techniques = []

        for pattern, technique in self.DOMAIN_TECHNIQUES.items():

            if pattern in domain:
                techniques.append(technique)

        return techniques

    def map_url(self, url):

        techniques = []

        for pattern, technique in self.URL_TECHNIQUES.items():

            if pattern in url:
                techniques.append(technique)

        return techniques
