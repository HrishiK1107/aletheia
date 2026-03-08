from abc import ABC, abstractmethod


class BaseCollector(ABC):
    """
    Base class for threat feed collectors.
    """

    name: str

    @abstractmethod
    def fetch(self):
        """
        Fetch raw indicators from feed.
        """
        pass

    @abstractmethod
    def parse(self, data):
        """
        Parse feed response into indicators.
        """
        pass

    def collect(self):
        """
        Fetch + parse pipeline.
        """
        data = self.fetch()
        indicators = self.parse(data)
        return indicators
