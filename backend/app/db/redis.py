from app.core.config import settings
from redis import Redis
from redis.exceptions import RedisError

redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def check_redis():
    try:
        redis_client.ping()
        return True
    except RedisError:
        return False
