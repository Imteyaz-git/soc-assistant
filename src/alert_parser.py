# ─────────────────────────────────────────────────────────────
# alert_parser.py
# Reads a security alert JSON file, parses it, and extracts
# the IOCs (Indicators of Compromise) for further analysis.
# ─────────────────────────────────────────────────────────────

import json  # Built-in Python library for reading and writing JSON
import os    # Built-in Python library for working with file paths


def load_alert(filepath):
    """
    Reads a JSON alert file from disk and returns it as a Python dictionary.

    Parameters:
        filepath (str): The path to the JSON file.

    Returns:
        dict: The alert data as a Python dictionary.
    """

    # Check if the file actually exists before trying to open it
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Alert file not found: {filepath}")

    # Open the file and read its contents
    with open(filepath, "r") as file:
        alert_data = json.load(file)  # Convert JSON text → Python dictionary

    return alert_data


def extract_iocs(alert_data):
    """
    Extracts IOCs (Indicators of Compromise) from a parsed alert dictionary.

    Parameters:
        alert_data (dict): The alert loaded from the JSON file.

    Returns:
        dict: A dictionary containing only the IOCs we care about.
    """

    iocs = {
        "destination_ip":  alert_data.get("destination_ip"),   # Suspicious IP address
        "destination_url": alert_data.get("destination_url"),  # Suspicious URL
        "file_hash":       alert_data.get("file_hash"),        # Suspicious file hash
    }

    return iocs


def parse_alert(filepath):
    """
    Master function — combines loading and IOC extraction in one step.
    This is the main function the rest of the project will call.

    Parameters:
        filepath (str): The path to the alert JSON file.

    Returns:
        tuple: (alert_data, iocs)
               alert_data = the full alert as a dictionary
               iocs       = just the extracted IOCs as a dictionary
    """

    alert_data = load_alert(filepath)    # Step 1: Load the file
    iocs = extract_iocs(alert_data)      # Step 2: Pull out the IOCs

    return alert_data, iocs