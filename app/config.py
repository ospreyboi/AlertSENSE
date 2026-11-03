import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ALERTSENSE_API_KEY", "")
DB_URL = os.getenv("ALERTSENSE_DB_URL", "sqlite:///alertsense.db")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_KEY = os.getenv("VT_API_KEY", "")
