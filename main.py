# ─────────────────────────────────────────────────────────────
# main.py
# Entry point for the SOC Assistant.
# Currently testing: alert parser + VirusTotal integration.
# ─────────────────────────────────────────────────────────────

from src.alert_parser import parse_alert
from src.virustotal import check_all_iocs

# ── Step 1: Parse the alert and extract IOCs ──────────────────
ALERT_PATH = "alerts/sample_alert_1.json"
alert_data, iocs = parse_alert(ALERT_PATH)

print("=" * 55)
print("🔍  EXTRACTED IOCs — Sending to VirusTotal...")
print("=" * 55)
print(f"  IP   : {iocs['destination_ip']}")
print(f"  URL  : {iocs['destination_url']}")
print(f"  Hash : {iocs['file_hash']}")
print()

# ── Step 2: Send IOCs to VirusTotal ───────────────────────────
vt_results = check_all_iocs(iocs)

# ── Step 3: Print the results ─────────────────────────────────
print("=" * 55)
print("🛡️   VIRUSTOTAL RESULTS")
print("=" * 55)

for key, result in vt_results.items():

    print(f"\n  IOC Type  : {result['ioc_type'].upper()}")
    print(f"  IOC Value : {result['ioc_value']}")

    if result["error"]:
        print(f"  ⚠️  Error  : {result['error']}")
    else:
        print(f"  🔴 Malicious  : {result['malicious']}")
        print(f"  🟡 Suspicious : {result['suspicious']}")
        print(f"  🟢 Harmless   : {result['harmless']}")
        print(f"  ⚪ Undetected : {result['undetected']}")

print()
print("=" * 55)