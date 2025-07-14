import whois

def enrich_domain_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        # Convert WHOIS data to dict and sanitize
        return {
            "domain": domain,
            "registrar": w.registrar,
            "name_servers": w.name_servers,
            "emails": w.emails,
            "status": w.status,
            "dnssec": w.dnssec,
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": str(e)
        }
