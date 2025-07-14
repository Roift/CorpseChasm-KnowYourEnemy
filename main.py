import click
from utils.ioc_parser import detect_ioc_type
from enrichers.abuseipdb import enrich_ip_abuseipdb
from utils.formatter import print_enrichment_table

@click.command()
@click.option('--ioc', help='Indicator of Compromise (IP, domain, hash)')
def enrich(ioc):
    ioc_type = detect_ioc_type(ioc)
    click.echo(f"[+] Detected IOC Type: {ioc_type}")

    if ioc_type == 'ip':
        result = enrich_ip_abuseipdb(ioc)
        print_enrichment_table(result)
    else:
        click.echo("[!] Enrichment for this IOC type not implemented yet.")


if __name__ == '__main__':
    enrich()
