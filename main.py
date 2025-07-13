import click

@click.command()
@click.option('--ioc', help='Indicator of Compromise (IP, domain, hash)')
def enrich(ioc):
    if not ioc:
        click.echo("Please provide an IOC with --ioc")
        return

    click.echo(f"Enriching: {ioc}")
    # Here we'll import enrichment functions later

if __name__ == '__main__':
    enrich()
