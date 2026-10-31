# db.py
# One shared connection to MongoDB for the whole project.
import os

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

_client = None  # created once, reused everywhere


def get_db():
    """Return the ReleaseGuard database."""
    global _client
    if _client is None:
        uri = os.getenv("MONGO_URI")
        if not uri:
            raise RuntimeError("MONGO_URI is missing. Check your .env file.")
        _client = MongoClient(uri, serverSelectionTimeoutMS=15000)
    return _client[os.getenv("DB_NAME", "releaseguard")]
