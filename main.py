# ─────────────────────────────────────────
# main.py - Temporary test
# Testing that config.py loads keys correctly
# ─────────────────────────────────────────

from src.config import VIRUSTOTAL_KEY, ABUSEIPDB_KEY, GEMINI_KEY

# Check each key was loaded — print Found or Missing
# We never print the actual key for security reasons

if VIRUSTOTAL_KEY:
    print("✅ VirusTotal key loaded successfully")
else:
    print("❌ VirusTotal key is MISSING — check your .env file")

if ABUSEIPDB_KEY:
    print("✅ AbuseIPDB key loaded successfully")
else:
    print("❌ AbuseIPDB key is MISSING — check your .env file")

if GEMINI_KEY:
    print("✅ Gemini key loaded successfully")
else:
    print("❌ Gemini key is MISSING — check your .env file")