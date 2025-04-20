import ipaddress
import sqlite3
import socket
import time
from models.models import get_db_connection

asn_cache = {}

def is_ip_allowed(ip):
    conn = get_db_connection()
    allowed_sources = conn.execute('SELECT * FROM allowed_api_sources').fetchall()
    conn.close()

    for source in allowed_sources:
        src_type = source["type"].lower()
        value = source["ip_or_cidr_or_asn"]

        if src_type == "ip":
            if ip == value:
                return True

        elif src_type == "cidr":
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False):
                    return True
            except ValueError:
                continue

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
        query = f" -v {ip}\n"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.cymru.com", 43))
        s.sendall(query.encode())

        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()

        lines = response.decode().splitlines()

        if len(lines) >= 2:
            parts = lines[1].split("|")
            if len(parts) > 0:
                asn = "AS" + parts[0].strip()
                asn_cache[ip] = (asn, current_time)
                return asn
    except Exception:
        return None