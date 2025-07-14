import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def enrich_domain_google_safebrowsing(domain: str) -> dict:
    url_to_check = f"http://{domain}"
    payload = {
        "client": {
            "clientId": "KnowYourEnemy",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }

    try:
        response = requests.post(API_URL, json=payload)
        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])
        if not matches:
            return {
                "domain": domain,
                "malicious": False,
                "details": []
            }
        else:
            # Extract info about threats found
            threat_details = []
            for match in matches:
                threat_details.append({
                    "threatType": match.get("threatType"),
                    "platformType": match.get("platformType"),
                    "threatEntryType": match.get("threatEntryType")
                })
            return {
                "domain": domain,
                "malicious": True,
                "details": threat_details
            }

    except Exception as e:
        return {
            "domain": domain,
            "malicious": False,
            "details": [],
            "error": str(e)
        }
