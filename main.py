# ─────────────────────────────────────────────────────────────
# main.py
# Entry point for the SOC Assistant.
# Currently testing:
#   - Alert parser
#   - VirusTotal integration
#   - AbuseIPDB integration
# ─────────────────────────────────────────────────────────────

from src.alert_parser import parse_alert
from src.virustotal import check_all_iocs
from src.abuseipdb import check_ip_reputation


# ── Step 1: Parse the alert and extract IOCs ──────────────────
ALERT_PATH = "alerts/sample_alert_1.json"
alert_data, iocs = parse_alert(ALERT_PATH)

print("=" * 55)
print("📋  ALERT SUMMARY")
print("=" * 55)
print(f"  Alert ID  : {alert_data['alert_id']}")
print(f"  Severity  : {alert_data['severity']}")
print(f"  Type      : {alert_data['alert_type']}")
print(f"  Host      : {alert_data['hostname']}")
print(f"  User      : {alert_data['username']}")
print()

print("=" * 55)
print("🔍  EXTRACTED IOCs")
print("=" * 55)
print(f"  IP   : {iocs['destination_ip']}")
print(f"  URL  : {iocs['destination_url']}")
print(f"  Hash : {iocs['file_hash']}")
print()


# ── Step 2: Send IOCs to VirusTotal ───────────────────────────
vt_results = check_all_iocs(iocs)

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


# ── Step 3: Send the suspicious IP to AbuseIPDB ───────────────
abuse_result = check_ip_reputation(iocs["destination_ip"])

print("=" * 55)
print("🌐  ABUSEIPDB RESULTS")
print("=" * 55)

if abuse_result["error"]:
    print(f"  ⚠️  Error : {abuse_result['error']}")
else:
    # Determine a simple threat label based on the confidence score
    score = abuse_result["abuse_confidence"]
    if score >= 80:
        threat_label = "🔴 HIGH THREAT"
    elif score >= 50:
        threat_label = "🟡 MODERATE THREAT"
    elif score >= 1:
        threat_label = "🟠 LOW THREAT"
    else:
        threat_label = "🟢 CLEAN"

    print(f"  IOC Value        : {abuse_result['ioc_value']}")
    print(f"  Threat Level     : {threat_label}")
    print(f"  Abuse Confidence : {abuse_result['abuse_confidence']}%")
    print(f"  Total Reports    : {abuse_result['total_reports']}")
    print(f"  Country          : {abuse_result['country_code']}")
    print(f"  ISP              : {abuse_result['isp']}")
    print(f"  Domain           : {abuse_result['domain']}")
    print(f"  Whitelisted      : {abuse_result['is_whitelisted']}")
    print(f"  Last Reported    : {abuse_result['last_reported_at']}")

print()
print("=" * 55)