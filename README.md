# CorpseChasm-KnowYourEnemy (KYE)

KnowYourEnemy is a command-line threat analysis Swiss Army knife. 
It provides fast, comprehensive enrichment of Indicators of Compromise (IOCs) such as IP addresses, domains, and file hashes by aggregating multiple threat intelligence sources into easy-to-read tables.

---

## Features

- **IP Enrichment**
  - Query **AbuseIPDB** to retrieve IP reputation, abuse scores, ISP, usage type, hostnames, domain, and country.
  - Query **VirusTotal** for IP reputation, network owner, country, tags, and detailed analysis stats.

- **File Hash Enrichment**
  - Query **VirusTotal** by file hash (MD5, SHA-1, SHA-256) to retrieve reputation, malware family identification, file type, submission history, tags, and detailed last analysis stats.

- **Domain Enrichment**
  - Query **VirusTotal** for domain reputation, analysis stats, registrar info, DNS records, and tags.
  - Query **Google Safe Browsing API** to check for malicious or phishing domain status.
  - Optional WHOIS lookup for detailed domain registration data such as registrar, creation, expiration, and update dates, DNSSEC status, and name servers (`--whois` flag).

- **Passive DNS Lookup** (`--pdns` flag)
  - Query **VirusTotal Passive DNS** to retrieve related IP addresses or domains.

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Roift/CorpseChasm-KnowYourEnemy
   cd KnowYourEnemy
   ```

2. Create and activate a Python virtual environment (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. Install package and dependencies using pip:
  ```bash
    pip install .
  ```

4. Create a `.env` file with your API keys:
  ```env
      VIRUSTOTAL_API_KEY=your_virustotal_api_key
      GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
      ABUSEIPDB_API_KEY=your_abuseipdb_api_key
  ```

---

## Usage
Basic command structure:
```bash
    kye --ioc <indicator> [--whois] [--pdns]
```

### Examples
- Enrich an IP address
```bash
    kye --ioc 8.8.8.8
```

- Enrich a domain and perform WHOIS lookup:
```bash
    kye --ioc example.com --whois
```

- Enrich a domain with Passive DNS lookups:
```bash
    kye --ioc example.com --pdns
```

Enrich a file hash (SHA-256):
```bash
    kye --ioc 44d88612fea8a8f36de82e1278abb02f
```

---

## Supported IOC Types
- IPv4 and IPv6 addresses
- Domain names
- File hashes (MD5, SHA-1, SHA-256)

---

## Output
All results are displayed in well-formatted, colored tables in the console using the `rich` library, providing clear visibility of:
- Reputation scores and statuses
- Related metadata (registrar info, ASN, ISP, tags)
- Historical data (submission dates, analysis timestamps)
- DNS records and passive DNS info
- WHOIS registration details

---

## Contributing
Contributions are welcome! Please open issues or submit pull requests to add new enrichers, improve formatting, or enhance functionality.

---
## Acknowledgements
- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Google Safe Browsing](https://safebrowsing.google.com/)
- [python-whois](https://github.com/joelverhagen/python-whois)
- [Rich](https://github.com/Textualize/rich)
- [Click](https://click.palletsprojects.com/)
- [python-dotenv](https://github.com/theskumar/python-dotenv)