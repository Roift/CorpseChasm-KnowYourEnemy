import os
import requests
from dotenv import load_dotenv

load_dotenv() # Load .env variables

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"

def enrich_ip_abuseipdb(ip: str) -> dict:
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True
    }

    try:
        response = requests.get(API_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()['data']

        return {
            "ip": data.get('ipAddress'),
            "reputation": "Malicious" if data.get('abuseConfidenceScore', 0) > 50 else "Clean",
            "abuse_score": data.get('abuseConfidenceScore', 0),
            "country": data.get('countryName') or data.get('countryCode', 'Unknown'),
            "isp": data.get('isp', 'Unknown'),
            "usage_type": data.get('usageType', 'Unknown'),
            "hostname": ", ".join(data.get('hostnames', [])) or data.get('domain', 'Unknown'),
            "domain": data.get('domain', 'Unknown')
        }
    except Exception as e:
        # Add logging here if needed
        return {
            "ip": ip,
            "reputation": "Unknown (API call failed)",
            "abuse_score": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "usage_type": "Unknown",
            "hostname": "Unknown",
        }