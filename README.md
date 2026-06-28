\# SOC Assistant — LLM-Powered Security Alert Analyzer



An AI-powered assistant that helps L1 SOC analysts automatically process

security alerts, enrich IOCs via threat intelligence APIs, and generate

structured summaries with escalation recommendations — in seconds.



\---



\## What It Does



1\. Receives a security alert

2\. Extracts IOCs (IP addresses, URLs, file hashes)

3\. Enriches each IOC using VirusTotal and AbuseIPDB APIs

4\. Sends all enriched data to an LLM (Claude or OpenAI)

5\. Returns a clean summary and escalation recommendation to the analyst



\---



\## Tech Stack



\- Python 3.x

\- Claude API (Anthropic) / OpenAI API

\- VirusTotal API

\- AbuseIPDB API

\- python-dotenv (secret management)

\- requests (HTTP calls)



\---



\## Project Structure

soc-assistant/



├── src/                  # All source code



│   ├── main.py           # Pipeline entry point



│   ├── alert\_parser.py   # Extracts IOCs from alerts



│   ├── virustotal.py     # VirusTotal API integration



│   ├── abuseipdb.py      # AbuseIPDB API integration



│   ├── llm\_handler.py    # LLM integration and prompting



│   └── output\_formatter.py  # Final report formatting



├── alerts/               # Sample security alerts for testing



├── logs/                 # Output logs



├── tests/                # Test scripts



├── .env                  # API keys (not uploaded to GitHub)



├── requirements.txt      # Python dependencies



└── README.md             # This file



\---



\## Status



🔧 Currently in active development — Phase 2 (Building)



\---



\## Author



Built by Imteyaz Ali as a practical cybersecurity + AI learning project.

