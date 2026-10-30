import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ALERTSENSE_API_KEY", "")
DB_URL = os.getenv("ALERTSENSE_DB_URL", "sqlite:///alertsense.db")
