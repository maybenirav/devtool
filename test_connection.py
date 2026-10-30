import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient

# 1. Read the connection string from the .env file
load_dotenv()
uri = os.getenv("MONGO_URI")

# 2. Connect to MongoDB Atlas
client = MongoClient(uri)

# 3. Check the connection works
client.admin.command("ping")
print("Connected to MongoDB!")

# 4. Choose a database and a collection
db = client["devtool"]
runs = db["runs"]

# 5. Save one document
runs.insert_one({
    "runId": "test-run-1",
    "projectId": "demo-project",
    "status": "passed",
    "createdAt": datetime.now(timezone.utc),
})
print("Saved a test run!")

# 6. Read back all documents and print them
for run in runs.find():
    print(run)
    