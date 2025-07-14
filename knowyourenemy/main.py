import click
from utils.ioc_parser import detect_ioc_type

from enrichers.abuseipdb import enrich_ip_abuseipdb
from enrichers.virustotalip import enrich_ip_virustotal
from enrichers.virustotalhash import enrich_hash_virustotal
from enrichers.virustotaldomain import enrich_domain_virustotal
from enrichers.googlesafebrowse import enrich_domain_google_safebrowsing
from enrichers.whois import enrich_domain_whois
from enrichers.virustotaldns import enrich_passive_dns_virustotal

from utils.formatter import print_abuseipdb_table
from utils.formatter import print_virustotal_ip_table
from utils.formatter import print_virustotal_hash_table
from utils.formatter import print_virustotal_domain_table
from utils.formatter import print_google_safebrowsing_table
from utils.formatter import print_whois_table
from utils.formatter import print_passive_dns_virustotal_table

@click.command()
@click.option('--ioc', help='Indicator of Compromise (IP, domain, hash)')
@click.option('--whois', is_flag=True, help='Perform WHOIS lookup for domain')
@click.option('--pdns', is_flag=True, help='Perform Passive DNS search for domain or IP')

def enrich(ioc, whois, pdns):
    ioc_type = detect_ioc_type(ioc)
    click.echo(f"[+] Detected IOC Type: {ioc_type}")

    if ioc_type == 'ip':
        abuseipdb_result = enrich_ip_abuseipdb(ioc)
        virustotal_ip_result = enrich_ip_virustotal(ioc)
        print_abuseipdb_table(abuseipdb_result)
        print_virustotal_ip_table(virustotal_ip_result)
        if pdns:
            virustotal_dns_result = enrich_passive_dns_virustotal(ioc)
            print_passive_dns_virustotal_table(virustotal_dns_result)


    elif ioc_type.startswith('hash'):
        virustotal_hash_result = enrich_hash_virustotal(ioc)
        print_virustotal_hash_table(virustotal_hash_result)

    elif ioc_type == 'domain':
        virustotal_domain_result = enrich_domain_virustotal(ioc)
        print_virustotal_domain_table(virustotal_domain_result)
        google_safebrowseing_domain_result = enrich_domain_google_safebrowsing(ioc)
        print_google_safebrowsing_table(google_safebrowseing_domain_result)
        if whois:
            whois_result = enrich_domain_whois(ioc)
            print_whois_table(whois_result)
        if pdns:
            virustotal_dns_result = enrich_passive_dns_virustotal(ioc)
            print_passive_dns_virustotal_table(virustotal_dns_result)


        
    else:
        click.echo("[!] Enrichment for this IOC type not implemented yet.")

if __name__ == '__main__':
    enrich()
