import os
import requests
from dotenv import load_dotenv

# Load security credentials from the .env configuration file
load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def enrich_ip_telemetry(ip_address):
    """
    Queries public Cyber Threat Intelligence (CTI) platforms 
    to extract geographical and behavioral indicators for an IOC.
    """
    # Defensive Check: Handle local testing loopback gracefully
    if ip_address == "127.0.0.1":
        return {
            "country_code": "INDIA",
            "isp": "Simulated Malicious ISP Node",
            "abuse_score": 85,
            "is_malicious": True,
            "threat_actor_guess": "Automated Brute-force botnet"
        }

    enrichment_data = {
        "country_code": "UNKNOWN",
        "isp": "UNKNOWN",
        "abuse_score": 0,
        "is_malicious": False,
        "threat_actor_guess": "Unknown Source"
    }

    if ABUSEIPDB_KEY:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_KEY}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                res_json = response.json().get('data', {})
                enrichment_data["country_code"] = res_json.get("countryCode", "UNKNOWN")
                enrichment_data["isp"] = res_json.get("isp", "UNKNOWN")
                enrichment_data["abuse_score"] = res_json.get("abuseConfidenceScore", 0)
                if enrichment_data["abuse_score"] >= 50:
                    enrichment_data["is_malicious"] = True
        except Exception as e:
            print(f"[-] CTI Operational Warning (AbuseIPDB): {e}")

    return enrichment_data