import os
import requests
from dotenv import load_dotenv

load_dotenv()  # Load .env variables

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

def enrich_domain_virustotal(domain: str) -> dict:
    headers = {
        "x-apikey": API_KEY
    }
    url = API_URL.format(domain=domain)

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json().get("data", {}).get("attributes", {})

        reputation_score = data.get("reputation", 0)
        analysis_stats = data.get("last_analysis_stats", {})
        tags = data.get("tags", [])
        last_analysis_date = data.get("last_analysis_date")
        registrar = data.get("registrar")
        creation_date = data.get("creation_date")
        last_dns_records = data.get("last_dns_records", [])
        last_dns_soa = data.get("last_dns_soa", {})

        if reputation_score < 0:
            reputation = "Malicious"
        elif reputation_score > 0:
            reputation = "Benign"
        else:
            reputation = "Unknown"

        return {
            "domain": domain,
            "reputation": reputation,
            "reputation_score": reputation_score,
            "last_analysis_stats": analysis_stats,
            "last_analysis_date": last_analysis_date,
            "tags": tags,
            "registrar": registrar,
            "creation_date": creation_date,
            "last_dns_records": last_dns_records,
            "last_dns_soa": last_dns_soa,
        }

    except Exception as e:
        print(f"[ERROR] VirusTotal Domain API call failed: {e}")
        return {
            "domain": domain,
            "reputation": "Unknown (VT API call failed)",
            "reputation_score": 0,
            "last_analysis_stats": {},
            "last_analysis_date": None,
            "tags": [],
            "registrar": None,
            "creation_date": None,
            "last_dns_records": [],
            "last_dns_soa": {},
        }
