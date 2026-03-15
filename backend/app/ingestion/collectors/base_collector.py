from abc import ABC, abstractmethod

from app.core.logging import get_logger

logger = get_logger(__name__)


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
        Safe fetch + parse pipeline.
        """

        try:
            data = self.fetch()
            indicators = self.parse(data)

            logger.info(f"{self.name} collected {len(indicators)} indicators")

            return indicators

        except Exception as e:
            logger.warning(f"{self.name} collector failed: {e}")
            return []
