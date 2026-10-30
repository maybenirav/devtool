# db.py
# One shared connection to MongoDB for the whole project.
import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

_client = None  # we create the connection once and reuse it


def get_db():
    """Return the ReleaseGuard database."""
    global _client
    if _client is None:
        uri = os.getenv("MONGO_URI")
        if not uri:
            raise RuntimeError("MONGO_URI is missing. Check your .env file.")
        _client = MongoClient(uri)
    return _client[os.getenv("DB_NAME", "releaseguard")]