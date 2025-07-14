import click
from utils.ioc_parser import detect_ioc_type

from enrichers.abuseipdb import enrich_ip_abuseipdb
from enrichers.virustotalip import enrich_ip_virustotal
from enrichers.virustotalhash import enrich_hash_virustotal

from utils.formatter import print_abuseipdb_table
from utils.formatter import print_virustotal_ip_table
from utils.formatter import print_virustotal_hash_table

@click.command()
@click.option('--ioc', help='Indicator of Compromise (IP, domain, hash)')
def enrich(ioc):
    ioc_type = detect_ioc_type(ioc)
    click.echo(f"[+] Detected IOC Type: {ioc_type}")

    if ioc_type == 'ip':
        abuseipdb_result = enrich_ip_abuseipdb(ioc)
        virustotal_ip_result = enrich_ip_virustotal(ioc)
        print_abuseipdb_table(abuseipdb_result)
        print_virustotal_ip_table(virustotal_ip_result)

    elif ioc_type.startswith('hash'):
        virustotal_hash_result = enrich_hash_virustotal(ioc)
        print_virustotal_hash_table(virustotal_hash_result)

    else:
        click.echo("[!] Enrichment for this IOC type not implemented yet.")

if __name__ == '__main__':
    enrich()
