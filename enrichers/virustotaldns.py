import os
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_DOMAIN_PDNS_URL = "https://www.virustotal.com/api/v3/domains/{domain}/historical_resolutions"

def enrich_passive_dns_virustotal(domain: str) -> dict:
    headers = {"x-apikey": VT_API_KEY}
    url = VT_DOMAIN_PDNS_URL.format(domain=domain)

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_data = response.json()

        # Extract list of historical resolutions (IPs and dates)
        resolutions = []
        for item in json_data.get("data", []):
            attrs = item.get("attributes", {})
            ip_address = attrs.get("ip_address")
            date = attrs.get("date")
            resolutions.append({"ip": ip_address, "date": date})

        return {
            "domain": domain,
            "resolutions": resolutions,
            "query_status": "ok"
        }
    except Exception as e:
        return {
            "domain": domain,
            "resolutions": [],
            "query_status": "error",
            "error": str(e)
        }
