import re
import ipaddress

def detect_ioc_type(ioc: str) -> str:
    try:
        ipaddress.ip_address(ioc)
        return 'ip'
    except ValueError:
        pass

    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    if re.match(domain_pattern, ioc):
        return 'domain'
    
    hash_patterns = {
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$',
    }

    for hash_type, pattern in hash_patterns.items():
        if re.match(pattern, ioc):
            return f'hash ({hash_type})'
        
    return 'unknown'