from abc import ABC, abstractmethod

from app.core.logging import get_logger

logger = get_logger(__name__)


class BaseCollector(ABC):
    """
    Base class for threat feed collectors.
    """

    name: str

    def __init__(self):
        # Set by collect() on failure so callers that need real observability
        # (collector_runner, for persisting per-run status) can tell an
        # actual error apart from a legitimately empty result -- collect()
        # itself keeps returning [] either way to stay a simple, safe call.
        self.last_error = None

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

        self.last_error = None

        try:
            data = self.fetch()
            indicators = self.parse(data)

            logger.info(f"{self.name} collected {len(indicators)} indicators")

            return indicators

        except Exception as e:
            self.last_error = str(e)
            logger.warning(f"{self.name} collector failed: {e}")
            return []
