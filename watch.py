import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()
client = MongoClient(os.getenv("MONGO_URI"))
runs = client["devtool"]["runs"]

print("Watching for new runs... (press Ctrl+C to stop)")

# Open a change stream on the 'runs' collection
with runs.watch() as stream:
    for change in stream:
        print("New change detected!")
        print("Type:", change["operationType"])
        print("Document:", change.get("fullDocument"))
        print("-" * 40)