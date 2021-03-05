REDIS = {
    "host": "redis",
    "port": 6379,
    "db": 0,
    "password": None
}

STATUS_TOKEN = ""

# used to change max file size on the fly. disabled completely if not set.
MAX_FILE_SIZE_TOKEN = ""

MAX_FILE_SIZE = 5 * 1000 ** 2  # 500 MB

UUID_SIZE = 5  # make this bigger if expecting more traffic
