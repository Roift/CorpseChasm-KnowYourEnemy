from rich.console import Console
from rich.table import Table

console = Console()

def print_enrichment_table(data: dict):
    table = Table(title=f"Enrichment for {data['ip']}")
    
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
