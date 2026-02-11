import os
from psycopg2 import pool as pg_pool

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")

_POOL = pg_pool.SimpleConnectionPool(
    1,
    10,
    dsn=DATABASE_URL,
    sslmode="require",
    connect_timeout=10
)

def get_connection():
    return _POOL.getconn()

def release_connection(conn):
    if conn:
        _POOL.putconn(conn)