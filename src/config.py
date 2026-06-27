# ─────────────────────────────────────────
# config.py
# Loads API keys from the .env file and
# makes them available to the whole project
# ─────────────────────────────────────────

import os
from dotenv import load_dotenv

# Read the .env file and load everything inside it into memory
load_dotenv()

# Read each key from the environment and store in a variable
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
GEMINI_KEY = os.getenv("GEMINI_KEY")