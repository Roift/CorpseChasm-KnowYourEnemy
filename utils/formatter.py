from rich.console import Console
from rich.table import Table
from datetime import datetime

console = Console()

def format_timestamp(ts):
    if not ts:
        return "N/A"
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')

def print_abuseipdb_table(data: dict):
    table = Table(title=f"AbuseIPDB Enrichment for {data['ip']}")
    
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Abuse Score", str(data["abuse_score"]))
    table.add_row("Reputation", data["reputation"])
    table.add_row("ISP", data["isp"])
    table.add_row("Usage Type", data["usage_type"])
    table.add_row("Hostnames", data["hostname"])
    table.add_row("Domain", data.get('domain', 'Unknown'))
    table.add_row("Country", data["country"])


    console.print(table)

def print_virustotal_ip_table(data: dict):
    table = Table(title=f"VirusTotal Enrichment for {data['ip']}")

    table.add_column("Field", style="bold green")
    table.add_column("Value", style="yellow")

    table.add_row("Reputation", str(data.get("reputation", "N/A")))
    table.add_row("Reputation Score", str(data.get("reputation_score", "N/A")))
    table.add_row("AS Owner", str(data.get("as_owner", "N/A")))
    table.add_row("Country", str(data.get("country", "N/A")))
    table.add_row("Network", str(data.get("network", "N/A")))

        # Format tags
    tags = data.get("tags", [])
    table.add_row("Tags", ", ".join(tags) if tags else "N/A")

    # Safely convert UNIX timestamp
    timestamp = data.get("last_analysis_date")
    if isinstance(timestamp, int):
        readable_date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        readable_date = "N/A"
    table.add_row("Last Analysis Date", readable_date)

    # Format last_analysis_stats
    last_analysis_stats = data.get("last_analysis_stats", {})
    stats_str = "\n".join(f"{k}: {v}" for k, v in last_analysis_stats.items()) if last_analysis_stats else "N/A"
    table.add_row("Last Analysis Stats", stats_str)

    console.print(table)

def print_virustotal_hash_table(data: dict):
        table = Table(title=f"VirusTotal Hash Enrichment for {data.get('hash', 'Unknown')}")

        table.add_column("Field", style="bold blue")
        table.add_column("Value", style="bright_white")

        table.add_row("Reputation", data.get("reputation", "N/A"))
        table.add_row("Type", data.get("type_description", "N/A"))
        table.add_row("Filename", data.get("meaningful_name", "N/A"))
        table.add_row("MD5", data.get("md5", "N/A"))
        table.add_row("SHA-1", data.get("sha1", "N/A"))
        table.add_row("SHA-256", data.get("sha256", "N/A"))
        table.add_row("Times Submitted", str(data.get("times_submitted", "N/A")))
        table.add_row("First Seen", format_timestamp(data.get("first_submission_date")))
        table.add_row("Last Seen", format_timestamp(data.get("last_submission_date")))
        tags = data.get("tags", [])
        table.add_row("Tags", ", ".join(tags) if tags else "N/A")

        stats = data.get("last_analysis_stats", {})
        if stats:
            stats_str = "\n".join(f"{k}: {v}" for k, v in stats.items())
        else:
            stats_str = "N/A"
        table.add_row("Last Analysis Stats", stats_str)

        console.print(table)

def print_virustotal_domain_table(data: dict):
    table = Table(title=f"VirusTotal Enrichment for {data.get('domain', 'Unknown Domain')}")

    table.add_column("Field", style="bold blue")
    table.add_column("Value", style="bright_white")

    table.add_row("Reputation", data.get("reputation", "N/A"))
    table.add_row("Reputation Score", str(data.get("reputation_score", "N/A")))

    # Format analysis stats
    analysis_stats = data.get("last_analysis_stats", {})
    stats_str = "\n".join(f"{k}: {v}" for k, v in analysis_stats.items()) if analysis_stats else "N/A"
    table.add_row("Last Analysis Stats", stats_str)

    # Last analysis date
    last_analysis_date = data.get("last_analysis_date")
    if isinstance(last_analysis_date, int):
        readable_date = datetime.utcfromtimestamp(last_analysis_date).strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        readable_date = "N/A"
    table.add_row("Last Analysis Date", readable_date)

    table.add_row("Registrar", data.get("registrar", "N/A"))

    # Creation date formatting (if it’s a Unix timestamp)
    creation_date = data.get("creation_date")
    if isinstance(creation_date, int):
        creation_str = datetime.utcfromtimestamp(creation_date).strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        creation_str = str(creation_date) if creation_date else "N/A"
    table.add_row("Creation Date", creation_str)

    # Tags
    tags = data.get("tags", [])
    table.add_row("Tags", ", ".join(tags) if tags else "N/A")

    # DNS Records
    dns_records = data.get("last_dns_records", [])
    dns_info = "\n".join([r.get("value", "") for r in dns_records if "value" in r]) if dns_records else "N/A"
    table.add_row("DNS Records", dns_info)

    # SOA Record
    soa = data.get("last_dns_soa", {})
    soa_info = "\n".join([f"{k}: {v}" for k, v in soa.items()]) if soa else "N/A"
    table.add_row("SOA Record", soa_info)

    # Optional: Add a VirusTotal GUI link for convenience
    if data.get("domain"):
        vt_url = f"https://www.virustotal.com/gui/domain/{data['domain']}/detection"
        table.add_row("VirusTotal Link", vt_url)

    console.print(table)
