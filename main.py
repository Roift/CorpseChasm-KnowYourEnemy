import click
from utils.ioc_parser import detect_ioc_type

@click.command()
@click.option('--ioc', help='Indicator of Compromise (IP, domain, hash)')
def enrich(ioc):
    ioc_type = detect_ioc_type(ioc)
    click.echo(f"IOC Detected: {ioc} (Type: {ioc_type})")

if __name__ == '__main__':
    enrich()
