import os
import requests
from dotenv import load_dotenv

load_dotenv() # Load .env variables

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

def enrich_ip_virustotal(ip: str) -> dict:
    headers = {
        "x-apikey": API_KEY
    }
    url = API_URL.format(ip=ip)

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()

        data = json_response.get("data",{}).get("attributes",{})

        reputation_score = data.get("reputation", 0)
        if reputation_score < 0:
            reputation = "Malicious"
        elif reputation_score > 0:
            reputation = "Benign"
        else:
            reputation = "Unknown"

        return {
            "ip": ip,
            "reputation": reputation,
            "reputation_score": reputation_score,
            "last_analysis_stats": data.get("last_analysis_stats", {}),
            "last_analysis_date": data.get("last_analysis_date"),
            "as_owner": data.get("as_owner"),
            "country": data.get("country"),
            "tags": data.get("tags", []),
            "network": data.get("network"),
        }
    except Exception as e:
        # can log exception here
        return {
            "ip": ip,
            "reputation": "Unknown (VT API call failed)",
            "reputation_score": 0,
            "last_analysis_stats": {},
            "last_analysis_date": None,
            "as_owner": None,
            "country": None,
            "tags": [],
            "network": None,
        }