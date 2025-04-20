import ipaddress
import sqlite3
import socket
import time
from models.models import get_db_connection
import dns.resolver


# In-memory cache for ASN lookups
asn_cache = {}

def is_ip_allowed(ip):
    conn = get_db_connection()
    allowed_sources = conn.execute('SELECT * FROM allowed_api_sources').fetchall()
    conn.close()

    for source in allowed_sources:
        src_type = source["type"].lower()  # In your DB, column is 'type'
        value = source["ip_or_cidr_or_asn"]  # In your DB, column is 'ip_or_cidr_or_asn'

        if src_type == "ip":
            if ip == value:
                return True

        elif src_type == "cidr":
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False):
                    return True
            except ValueError:
                continue  # Bad CIDR format in DB? Ignore this one safely

        elif src_type == "asn":
            asn = get_asn_for_ip(ip)
            if asn and asn.upper() == value.upper():
                return True

    return False

def get_asn_for_ip(ip):
    current_time = time.time()

    # Check cache first
    if ip in asn_cache:
        asn, timestamp = asn_cache[ip]
        if current_time - timestamp < 43200:  # 12 hours cache
            return asn

    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"

        # Resolve TXT record (correct for ASN lookup)
        answers = dns.resolver.resolve(query, "TXT")
        response = str(answers[0])

        # Response format typically: '"ASN | ..."' --> we extract ASN
        asn = "AS" + response.strip('"').split()[0]
        asn_cache[ip] = (asn, current_time)
        return asn
    except Exception:
        return None

    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        
        # Use socket timeout (important to avoid curl hangs)
        socket.setdefaulttimeout(5)
        
        response = socket.gethostbyname(query)
        
        asn = "AS" + response.split()[0]  # Take first ASN part
        asn_cache[ip] = (asn, current_time)
        return asn
    except Exception:
        return None