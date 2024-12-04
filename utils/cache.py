from functools import wraps
from flask import current_app, session
import json
from utils.redis_helper import RedisHelper

class CacheTimeout:
    # Very short-lived cache (few seconds)
    REALTIME = 5  # 5 seconds
    
    # Short-lived cache (minutes)
    VERY_SHORT = 60  # 1 minute
    SHORT = 300  # 5 minutes
    MEDIUM_SHORT = 900  # 15 minutes
    
    # Medium-lived cache (hours)
    MEDIUM = 3600  # 1 hour
    MEDIUM_LONG = 7200  # 2 hours
    LONG = 21600  # 6 hours
    
    # Long-lived cache (days)
    VERY_LONG = 86400  # 1 day
    ETERNAL = 604800  # 1 week

class Cache:
    @staticmethod
    def key_builder(*args, **kwargs):
        """Build a cache key based on arguments"""
        key_parts = [str(arg) for arg in args]
        key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
        return None if len(key_parts) == 0 else ":".join(key_parts)

    # @staticmethod
    # def cache_key(prefix):
    #     """Generate a cache key with prefix"""
    #     def decorator(f):
    #         @wraps(f)
    #         def wrapper(*args, **kwargs):
    #             # Get the function's cache key
    #             key = f"{prefix}:user_id:{session['user_id']}:{Cache.key_builder(*args, **kwargs)}"
    #             return key
    #         return wrapper
    #     return decorator

    @staticmethod
    def cached(prefix, timeout=CacheTimeout.MEDIUM):
        """Cache decorator for functions/methods"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                try:
                    redis_client = RedisHelper.get_instance()
                    cache_key = [prefix]
                    arg_key = Cache.key_builder(*args, **kwargs)
                    if arg_key:
                        cache_key.append(arg_key)
                    else:
                        cache_key.append(str(session['user_id']))
                    cache_key = ":".join(cache_key)

                    current_app.logger.info(f"cache_key: {cache_key}")
                    
                    # Try to get cached value
                    cached_value = redis_client.get(cache_key)
                    if cached_value:
                        return json.loads(cached_value)
                    
                    # If not cached, execute function
                    value = f(*args, **kwargs)
                    
                    # Cache the result
                    # Handle jsonify response objects
                    if hasattr(value, 'get_json'):
                        cache_value = json.dumps(value.get_json())
                    else:
                        cache_value = value if isinstance(value, str) else json.dumps(value)
                    
                    redis_client.setex(
                        cache_key,
                        timeout,
                        cache_value
                    )
                    
                    return value
                except Exception as e:
                    current_app.logger.error(f"Cache error in {f.__name__}: {str(e)}")
                    # Fall back to uncached function
                    return f(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def invalidate(prefix, *args, **kwargs):
        """Invalidate cache for given prefix and arguments"""
        try:
            redis_client = RedisHelper.get_instance()
            pattern = f"{prefix}:*"
            
            # Delete all keys matching the pattern
            for key in redis_client.scan_iter(match=prefix):
                redis_client.delete(key)
        except Exception as e:
            current_app.logger.error(f"Cache invalidation error: {str(e)}")

    def invalidate_user_info_cache(user_id):
        """Invalidate user info cache"""
        Cache.invalidate(f'user_info:{user_id}')
    
    def invalidate_user_cvs_cache(user_id):
        """Invalidate user cvs cache"""
        current_app.logger.debug(f"Invalidating user cvs cache for user {user_id}")
        Cache.invalidate(f'user_cvs:{user_id}')

    def invalidate_cv_cache(cv_id):
        """Invalidate CV and related caches"""
        current_app.logger.debug(f"Invalidating CV {cv_id}")
        Cache.invalidate(f'cv:cv_id:{cv_id}')
    
    def invalidate_user_cache(user_id):
        """Invalidate all user-related caches"""
        Cache.invalidate_user_info_cache(user_id)
        Cache.invalidate_user_cvs_cache(user_id)

    def invalidate_user_cv_cache(cv_id, user_id):
        """Invalidate CV and related caches"""
        current_app.logger.debug(f"Invalidating CV {cv_id} and related caches for user {user_id}")
        Cache.invalidate_cv_cache(cv_id)
        Cache.invalidate_user_cvs_cache(user_id)
