# ─────────────────────────────────────────────────────────────
# virustotal.py
# Queries the VirusTotal API for threat intelligence on:
#   - IP addresses
#   - URLs
#   - File hashes
# Returns a clean summary dict for each IOC checked.
# ─────────────────────────────────────────────────────────────

import requests   # For making HTTP requests to the API
import base64     # For encoding URLs before sending to VirusTotal
import json       # For pretty-printing during debug (optional but useful)

from src.config import VIRUSTOTAL_KEY  # Our API key from .env


# ── Base URL that all VirusTotal API endpoints start with ─────
BASE_URL = "https://www.virustotal.com/api/v3"


def _get_headers():
    """
    Returns the headers required by every VirusTotal API request.
    The API key goes in the header, not the URL.
    """
    return {
        "x-apikey": VIRUSTOTAL_KEY
    }


def check_ip(ip_address):
    """
    Queries VirusTotal for a report on a given IP address.

    Parameters:
        ip_address (str): The IP to check, e.g. "185.220.101.45"

    Returns:
        dict: A clean summary with the verdict and detection counts.
    """

    # Build the full endpoint URL for IP lookup
    url = f"{BASE_URL}/ip_addresses/{ip_address}"

    try:
        # Send a GET request to VirusTotal with our API key in the headers
        response = requests.get(url, headers=_get_headers())

        # If VirusTotal returned an error status (e.g. 404, 401), raise it now
        response.raise_for_status()

        # Convert the JSON response into a Python dictionary
        data = response.json()

        # Navigate into the nested JSON to find the stats we care about
        stats = data["data"]["attributes"]["last_analysis_stats"]

        # Return a clean, simple summary
        return {
            "ioc_type":   "ip",
            "ioc_value":  ip_address,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "error":      None
        }

    except requests.exceptions.HTTPError as e:
        # API returned an error status code (e.g. 401 Unauthorized, 404 Not Found)
        return _error_result("ip", ip_address, f"HTTP error: {e}")

    except requests.exceptions.ConnectionError:
        # No internet connection, or VirusTotal is unreachable
        return _error_result("ip", ip_address, "Connection error — check your internet")

    except KeyError:
        # The JSON response didn't have the fields we expected
        return _error_result("ip", ip_address, "Unexpected response structure from VirusTotal")


def check_url(url_to_check):
    """
    Queries VirusTotal for a report on a given URL.
    VirusTotal requires the URL to be Base64-encoded before sending.

    Parameters:
        url_to_check (str): The URL to check.

    Returns:
        dict: A clean summary with the verdict and detection counts.
    """

    # Base64-encode the URL (VirusTotal requirement)
    # strip("=") removes the padding characters at the end — VT doesn't want them
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

    # Build the full endpoint URL for URL lookup
    endpoint = f"{BASE_URL}/urls/{url_id}"

    try:
        response = requests.get(endpoint, headers=_get_headers())
        response.raise_for_status()

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ioc_type":   "url",
            "ioc_value":  url_to_check,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "error":      None
        }

    except requests.exceptions.HTTPError as e:
        return _error_result("url", url_to_check, f"HTTP error: {e}")

    except requests.exceptions.ConnectionError:
        return _error_result("url", url_to_check, "Connection error — check your internet")

    except KeyError:
        return _error_result("url", url_to_check, "Unexpected response structure from VirusTotal")


def check_hash(file_hash):
    """
    Queries VirusTotal for a report on a given file hash (MD5, SHA1, or SHA256).

    Parameters:
        file_hash (str): The hash to check.

    Returns:
        dict: A clean summary with the verdict and detection counts.
    """

    # Build the full endpoint URL for file hash lookup
    url = f"{BASE_URL}/files/{file_hash}"

    try:
        response = requests.get(url, headers=_get_headers())
        response.raise_for_status()

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ioc_type":   "hash",
            "ioc_value":  file_hash,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "error":      None
        }

    except requests.exceptions.HTTPError as e:
        return _error_result("hash", file_hash, f"HTTP error: {e}")

    except requests.exceptions.ConnectionError:
        return _error_result("hash", file_hash, "Connection error — check your internet")

    except KeyError:
        return _error_result("hash", file_hash, "Unexpected response structure from VirusTotal")


def check_all_iocs(iocs):
    """
    Master function — runs all three checks (IP, URL, hash) at once.
    This is the main function the rest of the project will call.

    Parameters:
        iocs (dict): The IOC dictionary returned by alert_parser.py

    Returns:
        dict: All three VirusTotal results in one place.
    """

    results = {}

    # Only check an IOC if it actually exists in the alert (not None)
    if iocs.get("destination_ip"):
        results["ip"] = check_ip(iocs["destination_ip"])

    if iocs.get("destination_url"):
        results["url"] = check_url(iocs["destination_url"])

    if iocs.get("file_hash"):
        results["hash"] = check_hash(iocs["file_hash"])

    return results


def _error_result(ioc_type, ioc_value, message):
    """
    Helper function — returns a consistent error dictionary
    instead of crashing when something goes wrong.

    Parameters:
        ioc_type  (str): "ip", "url", or "hash"
        ioc_value (str): The actual IOC string
        message   (str): What went wrong

    Returns:
        dict: A clean error result in the same format as a normal result.
    """
    return {
        "ioc_type":   ioc_type,
        "ioc_value":  ioc_value,
        "malicious":  None,
        "suspicious": None,
        "harmless":   None,
        "undetected": None,
        "error":      message
    }