import json
import time
from functools import wraps
from flask import request, jsonify, current_app
from redis import RedisError
from utils.redis_helper import RedisHelper


# Define rate limits for different endpoints
class RateLimits:
    DEFAULT = {'requests': 60, 'window': 60}    # 60 requests per minute
    STRICT = {'requests': 1, 'window': 10}    # 1 request per 10 seconds
    PROCESS = {'requests': 10, 'window': 60}    # 10 extractions per minute
    LOGIN = {'requests': 5, 'window': 300}      # 5 attempts per 5 minutes
    REGISTER = {'requests': 3, 'window': 300}   # 3 attempts per 5 minutes
    VERIFY_EMAIL = {'requests': 5, 'window': 300} # 5 attempts per 5 minutes
    RESEND_VERIFICATION = {'requests': 2, 'window': 300} # 2 attempts per 5 minutes
    GENERATE_PAYMENT_TOKEN = {'requests': 5, 'window': 300} # 5 attempts per 5 minutes
    CREATE_CV = {'requests': 1, 'window': 5} # 1 attempt per 5 seconds
    RENAME_CV = {'requests': 1, 'window': 5} # 1 attempt per 5 seconds
    DUPLICATE_CV = {'requests': 1, 'window': 5} # 1 attempt per 5 seconds
    DELETE_CV = {'requests': 1, 'window': 5} # 1 attempt per 5 seconds
    UPDATE_CV = {'requests': 1, 'window': 5} # 1 attempt per 5 seconds
    REQUEST_PASSWORD_RESET = {'requests': 3, 'window': 300} # 3 attempts per 5 minutes
    RESET_PASSWORD = {'requests': 1, 'window': 5} # 1 attempt per 5 seconds
    RESEND_PASSWORD_RESET = {'requests': 2, 'window': 300} # 2 attempts per 5 minutes

class RateLimitExceeded(Exception):
    pass

class RateLimiter:
    def rate_limit(requests=60, window=60):
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    # Initialize Redis
                    redis_client = RedisHelper.get_instance()
                except RedisError as e:
                    # Fallback to allow request if Redis is down
                    return f(*args, **kwargs)
                
                identifier = f"ip:{request.remote_addr}"

                # Create unique key for this endpoint
                endpoint = request.endpoint
                key = f"rate_limit:{identifier}:{endpoint}"

                try:
                    # Get current timestamp
                    now = int(time.time())
                    window_start = now - window

                    # Create pipeline for atomic operations
                    pipe = redis_client.pipeline()
                    
                    # Remove old requests outside the window
                    pipe.zremrangebyscore(key, 0, window_start)
                    
                    # Count requests in current window
                    pipe.zcard(key)
                    
                    # Add current request
                    pipe.zadd(key, {str(now): now})
                    
                    # Set expiry on the key
                    pipe.expire(key, window)
                    
                    # Execute pipeline
                    _, request_count, *_ = pipe.execute()

                    # Check if limit exceeded
                    if request_count >= requests:
                        raise RateLimitExceeded

                    # Add rate limit headers
                    response = f(*args, **kwargs)
                    if isinstance(response, tuple):
                        response_obj, status_code = response
                    else:
                        response_obj, status_code = response, 200

                    if isinstance(response_obj, (dict, list)):
                        response_obj = jsonify(response_obj)
                    
                    remaining = requests - request_count
                    reset_time = window_start + window

                    response_obj.headers['X-RateLimit-Limit'] = str(requests)
                    response_obj.headers['X-RateLimit-Remaining'] = str(remaining)
                    response_obj.headers['X-RateLimit-Reset'] = str(reset_time)

                    return response_obj, status_code

                except RedisError as e:
                    return f(*args, **kwargs)
                
                except RateLimitExceeded:
                    response = jsonify({
                        'error': 'Rate limit exceeded',
                        'message': f'Too many requests. Please try again in {window} seconds.'
                    })
                    response.status_code = 429
                    return response

            return decorated_function
        return decorator

