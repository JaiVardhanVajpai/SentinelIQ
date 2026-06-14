from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = AsyncIOMotorClient(MONGO_URI)
db = client["sentineliq"]
investigations_collection = db["investigations"]

def get_db():
    return investigations_collection

print("[OK] MongoDB connected to SentinelIQ database")
