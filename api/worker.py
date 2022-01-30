# Worker that removes expired files
import time

from redis import Redis
import os

REDIS = {
    "host": "redis",
    "port": 6379,
    "db": 0,
    "password": None
}
CURRENT_TIME = time.time()

redis = Redis(**REDIS)


def check_file(filename: str) -> int:
    id_ = bytes.fromhex(filename).decode()
    expiration = int(redis.get("expire-" + id_) or -1)
    if CURRENT_TIME > expiration > 0:
        os.remove("/mount/upload/" + filename)
        redis.delete("metadata-" + id_, "revocation-" + id_, "expire-" + id_)
        return 1
    return 0


if __name__ == '__main__':
    # explicitly flush because of nohup
    print("Started cleanup script", flush=True)
    while True:
        CURRENT_TIME = time.time()
        deleted = 0
        for file in os.scandir("/mount/upload"):
            if file.name == ".keep":
                continue
            deleted += check_file(file.name)
        if deleted > 0:
            print(f"Deleted {deleted} files", flush=True)

        # clean up old unfinished sessions
        for partial in os.scandir("/mount/partial"):
            if partial.name == ".keep":
                continue
            if not redis.exists("session-" + partial.name):
                os.remove("/mount/partial/" + partial.name)
        time.sleep(3600)
