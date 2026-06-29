# ─────────────────────────────────────────────────────────────
# main.py
# Entry point for the SOC Assistant.
# Currently used to test the alert parser.
# ─────────────────────────────────────────────────────────────

from src.alert_parser import parse_alert  # Import our parser function

# Path to our sample alert file
ALERT_PATH = "alerts/sample_alert_1.json"

# Run the parser
alert_data, iocs = parse_alert(ALERT_PATH)

# Print the full alert details
print("=" * 55)
print("📋  FULL ALERT DATA")
print("=" * 55)
print(f"  Alert ID   : {alert_data['alert_id']}")
print(f"  Timestamp  : {alert_data['timestamp']}")
print(f"  Severity   : {alert_data['severity']}")
print(f"  Type       : {alert_data['alert_type']}")
print(f"  Source IP  : {alert_data['source_ip']}")
print(f"  Host       : {alert_data['hostname']}")
print(f"  User       : {alert_data['username']}")
print(f"  Department : {alert_data['department']}")
print()

# Print just the extracted IOCs
print("=" * 55)
print("🔍  EXTRACTED IOCs")
print("=" * 55)
print(f"  Destination IP  : {iocs['destination_ip']}")
print(f"  Destination URL : {iocs['destination_url']}")
print(f"  File Hash       : {iocs['file_hash']}")
print("=" * 55)