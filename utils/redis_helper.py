import redis
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class RedisHelper:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            try:
                cls._instance = redis.Redis(
                    host=current_app.config['REDIS_HOST'],
                    port=current_app.config['REDIS_PORT'],
                    password=current_app.config['REDIS_PASSWORD'],
                    db=current_app.config['REDIS_DB'],
                    decode_responses=True,
                    socket_timeout=2,
                    socket_connect_timeout=2,
                    retry_on_timeout=True
                )
                # Test connection
                cls._instance.ping()
            except redis.RedisError as e:
                logger.error(f"Failed to connect to Redis: {str(e)}")
                cls._instance = None
                raise
        return cls._instance

    @classmethod
    def reset_instance(cls):
        cls._instance = None