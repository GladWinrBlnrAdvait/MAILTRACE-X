import functools
import threading
import time

# Statuses that are real answers and safe to remember.
# Failures (timeout, error, lookup_failed, no_api_key) are NOT in this set,
# so a temporary problem is retried next time instead of being stored.
CACHEABLE_STATUSES = {"ok", "nxdomain", "private_or_reserved", "invalid_ip"}


def cached(ttl_seconds: int = 3600, maxsize: int = 2048):
    """Cache a lookup function's result for a limited time, successes only."""

    def decorator(func):
        store = {}              # argument -> (expiry_time, result)
        lock = threading.Lock() # lookups may run in several threads

        @functools.wraps(func)
        def wrapper(arg):
            now = time.monotonic()
            with lock:
                hit = store.get(arg)
                if hit and hit[0] > now:
                    return hit[1]

            result = func(arg)

            if result.get("status") in CACHEABLE_STATUSES:
                with lock:
                    if len(store) >= maxsize:
                        store.pop(next(iter(store)))   # drop the oldest entry
                    store[arg] = (now + ttl_seconds, result)
            return result

        wrapper.cache_clear = store.clear
        return wrapper

    return decorator
