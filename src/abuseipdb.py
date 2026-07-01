# ─────────────────────────────────────────────────────────────
# abuseipdb.py
# Queries the AbuseIPDB API for IP reputation intelligence
# based on real-world abuse reports from the security community.
#
# AbuseIPDB specializes in IPs only — it tells us:
#   - How many organizations have reported this IP
#   - How confident AbuseIPDB is that it's malicious (0-100%)
#   - Where the IP is located and who owns it
#   - When it was last reported
# ─────────────────────────────────────────────────────────────

import requests  # For making HTTP requests to the API

from src.config import ABUSEIPDB_KEY  # Our API key from .env


# ── The single AbuseIPDB endpoint we need ─────────────────────
BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip_address, max_age_days=90):
    """
    Queries AbuseIPDB for reputation data on a given IP address.

    Parameters:
        ip_address   (str): The IP to check, e.g. "185.220.101.45"
        max_age_days (int): Only count reports within this many days.
                            Default is 90 — the standard analysis window.

    Returns:
        dict: A clean summary containing the abuse score, report count,
              location, ISP, and other relevant reputation data.
    """

    # ── Build the request headers ──────────────────────────────
    # AbuseIPDB requires the API key in a header called "Key"
    # We also tell it we want the response in JSON format
    headers = {
        "Key":    ABUSEIPDB_KEY,
        "Accept": "application/json"
    }

    # ── Build the query parameters ─────────────────────────────
    # These get automatically appended to the URL by requests:
    # ?ipAddress=185.220.101.45&maxAgeInDays=90&verbose
    # "verbose" tells AbuseIPDB to include extra detail in the response
    params = {
        "ipAddress":    ip_address,
        "maxAgeInDays": max_age_days,
        "verbose":      ""            # Empty string enables verbose mode
    }

    try:
        # ── Send the GET request ───────────────────────────────
        response = requests.get(BASE_URL, headers=headers, params=params)

        # If AbuseIPDB returned an error status, raise it immediately
        response.raise_for_status()

        # Convert the JSON response into a Python dictionary
        data = response.json()

        # AbuseIPDB wraps all results inside a "data" key
        report = data["data"]

        # ── Return a clean, structured summary ─────────────────
        return {
            "ioc_type":         "ip",
            "ioc_value":        ip_address,
            "abuse_confidence": report.get("abuseConfidenceScore", 0),
            "total_reports":    report.get("totalReports", 0),
            "country_code":     report.get("countryCode", "Unknown"),
            "isp":              report.get("isp", "Unknown"),
            "domain":           report.get("domain", "Unknown"),
            "is_whitelisted":   report.get("isWhitelisted", False),
            "last_reported_at": report.get("lastReportedAt", "Never"),
            "error":            None
        }

    except requests.exceptions.HTTPError as e:
        # AbuseIPDB returned an error status code (401, 422, 429, etc.)
        return _error_result(ip_address, f"HTTP error: {e}")

    except requests.exceptions.ConnectionError:
        # No internet connection, or AbuseIPDB is unreachable
        return _error_result(ip_address, "Connection error — check your internet")

    except KeyError:
        # The JSON response didn't contain the fields we expected
        return _error_result(ip_address, "Unexpected response structure from AbuseIPDB")


def _error_result(ip_address, message):
    """
    Helper function — returns a consistent error dictionary
    instead of crashing when something goes wrong.

    Every field is set to None so the rest of the pipeline
    always receives the same dictionary shape, error or not.

    Parameters:
        ip_address (str): The IP that was being checked
        message    (str): A description of what went wrong

    Returns:
        dict: A clean error result matching the normal result format.
    """
    return {
        "ioc_type":         "ip",
        "ioc_value":        ip_address,
        "abuse_confidence": None,
        "total_reports":    None,
        "country_code":     None,
        "isp":              None,
        "domain":           None,
        "is_whitelisted":   None,
        "last_reported_at": None,
        "error":            message
    }