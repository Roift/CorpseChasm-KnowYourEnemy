import os
import requests
from dotenv import load_dotenv

load_dotenv()  # Load .env variables

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
API_URL = "https://www.virustotal.com/api/v3/files/{hash}"

def enrich_hash_virustotal(hash_value: str) -> dict:
    headers = {
        "x-apikey": API_KEY
    }
    url = API_URL.format(hash=hash_value)

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()

        data = json_response.get("data", {}).get("attributes", {})
        classification = data.get("popular_threat_classification", {})
        malware_family = classification.get("suggested_threat_label", "N/A")


        # Basic reputation info
        malicious_count = data.get("last_analysis_stats", {}).get("malicious", 0)
        suspicious_count = data.get("last_analysis_stats", {}).get("suspicious", 0)
        reputation_score = data.get("reputation", 0)

        reputation = "Malicious" if malicious_count > 0 else "Suspicious" if suspicious_count > 0 else "Clean"

        return {
            "hash": hash_value,
            "reputation": reputation,
            "reputation_score": reputation_score,
            "type_description": data.get("type_description"),
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "last_analysis_date": data.get("last_analysis_date"),
            "last_analysis_stats": data.get("last_analysis_stats", {}),
            "meaningful_name": data.get("meaningful_name"),
            "tags": data.get("tags", []),
            "trid": data.get("trid", []),  # file type signatures
            "times_submitted": data.get("times_submitted", 0),
            "first_submission_date": data.get("first_submission_date"),
            "last_submission_date": data.get("last_submission_date"),
            "malware_family": malware_family,
        }

    except Exception as e:
        # You can add logging here
        return {
            "hash": hash_value,
            "reputation": "Unknown (VT API call failed)",
            "reputation_score": 0,
            "type_description": None,
            "md5": None,
            "sha1": None,
            "sha256": None,
            "last_analysis_date": None,
            "last_analysis_stats": {},
            "meaningful_name": None,
            "tags": [],
            "trid": [],
            "times_submitted": 0,
            "first_submission_date": None,
            "last_submission_date": None,
        }