import ipaddress
import sqlite3
import socket
import time
from models.models import get_db_connection,

asn_cache = {}

def is_ip_allowed(ip):
    conn = get_db_connection()
    allowed_sources = conn.execute('SELECT * FROM allowed_api_sources').fetchall()
    conn.close()

    for source in allowed_sources:
        src_type = source["source_type"]
        value = source["value"]

        if src_type == "ip":
            if ip == value:
                return True
        elif src_type == "cidr":
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(value):
                    return True
            except ValueError:
                continue
        elif src_type == "asn":
            asn = get_asn_for_ip(ip)
            if asn and asn == value.upper():
                return True

    return False

def get_asn_for_ip(ip):
    current_time = time.time()
    if ip in asn_cache:
        asn, timestamp = asn_cache[ip]
        if current_time - timestamp < 43200:  # 12 hours
            return asn

    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        answer = socket.gethostbyname(query)
        asn = "AS" + answer.split(" ")[0]
        asn_cache[ip] = (asn, current_time)
        return asn
    except Exception:
        return None