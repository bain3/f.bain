import os

from redis import Redis

REDIS = {"host": "redis", "port": 6379, "db": 0, "password": None}

redis = Redis(**REDIS)

redis.setnx("count", 0)
redis.set("maxfs", os.getenv("MAX_FILE_SIZE", 5 * 1000 ^ 2 * 100))
