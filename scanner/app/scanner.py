"""
scanner.py - Periodic Nmap-based network scanner for LANStalker.
Scans the network segment, detects active hosts via ARP,
and runs full Nmap scans to extract detailed information.
"""

import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from time import sleep
from dotenv import load_dotenv
from flask import Flask
import logging

from db import (
    db,
    init_app,
    insert_or_update_host,
    insert_ports,
    get_all_known_macs,
    update_host_status,
    Host,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)

# Load environment variables
load_dotenv()

NETWORK_SEGMENT = os.getenv("NETWORK_SEGMENT")
SCAN_FREQUENCY = int(os.getenv("SCAN_FREQUENCY", 300))
DB_PATH = os.getenv("DB_PATH", "/db/network.db")
XMLS_PATH = os.getenv("XMLS_PATH", "/xmls")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "TELEGRAM_CHAT_ID")

if not NETWORK_SEGMENT:
    raise ValueError("NETWORK_SEGMENT environment variable is not set.")
logging.info(f"Scanning network segment: {NETWORK_SEGMENT}")
logging.info(f"Scan frequency: {SCAN_FREQUENCY} seconds")
logging.info(f"Using database at: {DB_PATH}")
logging.info(f"Processing XMLs from: {XMLS_PATH}")

if TELEGRAM_TOKEN == "TELEGRAM_TOKEN" or TELEGRAM_CHAT_ID == "TELEGRAM_CHAT_ID":
    logging.warning(
        "Telegram notifications are disabled. Set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID to enable."
    )
    TELEGRAM = False
else:
    TELEGRAM = True  # Placeholder if later you add the function to send alerts

# Flask app for DB context
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
init_app(app)


def run_ping_scan():
    """Performs an ARP discovery scan to find active hosts with MAC addresses."""
    logging.info("Running ARP discovery (ping scan with MAC resolution)...")
    result = subprocess.run(
        ["nmap", "-sn", "-n", "-oX", "-", NETWORK_SEGMENT],
        capture_output=True,
        text=True,
    )
    root = ET.fromstring(result.stdout)
    macs_and_ips = []
    for host in root.findall("host"):
        status = host.find("status").attrib["state"]
        if status != "up":
            continue
        ip = None
        mac = None
        for addr in host.findall("address"):
            if addr.attrib["addrtype"] == "ipv4":
                ip = addr.attrib["addr"]
            elif addr.attrib["addrtype"] == "mac":
                mac = addr.attrib["addr"].upper()
        if mac:
            macs_and_ips.append((mac, ip))
    logging.info(f"Active hosts with MAC addresses: {len(macs_and_ips)}")
    return macs_and_ips


def run_full_scan(ip):
    """Runs a detailed Nmap scan on the specified IP address."""
    logging.info(f"Running full scan on {ip}...")
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    output_file = os.path.join(XMLS_PATH, f"scan_{timestamp}.xml")
    logging.info(f"Writing scan output to {output_file}")
    subprocess.run(
        ["nmap", "-sS", "-sV", "--allports", "-T4", "-oX", output_file, ip],
        check=True,
    )
    process_scan(output_file)
    os.remove(output_file)
    logging.info("Scan completed.")


def parse_nmap_xml(xml_file):
    """Parses an Nmap XML file and extracts host data."""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []
    for host in root.findall("host"):
        status = host.find("status").attrib["state"]
        if status != "up":
            continue
        ip = None
        mac = None
        vendor = None
        hostname = None
        os_name = None
        ports = []
        for addr in host.findall("address"):
            if addr.attrib["addrtype"] == "ipv4":
                ip = addr.attrib["addr"]
            elif addr.attrib["addrtype"] == "mac":
                mac = addr.attrib["addr"].upper()
                vendor = addr.attrib.get("vendor")
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.attrib.get("name")
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.attrib.get("name")
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                port_id = int(port.attrib["portid"])
                protocol = port.attrib["protocol"]
                state = port.find("state").attrib["state"]
                service_elem = port.find("service")
                service = (
                    service_elem.attrib.get("name")
                    if service_elem is not None
                    else None
                )
                version = (
                    service_elem.attrib.get("version")
                    if service_elem is not None
                    else None
                )
                product = (
                    service_elem.attrib.get("product")
                    if service_elem is not None
                    else None
                )
                ports.append(
                    {
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                    }
                )
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "os": os_name,
                "ports": ports,
            }
        )
    return hosts


def process_scan(scan_file):
    """Insert parsed scan results into the database and log IP changes."""
    hosts = parse_nmap_xml(scan_file)
    online_macs = set()
    for host in hosts:
        is_new, ip_changed, host_id = insert_or_update_host(
            mac=host["mac"],
            ip=host["ip"],
            vendor=host.get("vendor"),
            hostname=host.get("hostname"),
            os_name=host.get("os"),
        )
        update_host_status(host["mac"], True)
        online_macs.add(host["mac"])
        insert_ports(host_id, host["ports"])
        if is_new:
            msg = f"New host discovered: {host['ip']} ({host.get('mac', 'N/A')})"
            logging.info(msg)
        elif ip_changed:
            msg = f"MAC {host['mac']} changed IP: now {host['ip']}"
            logging.warning(msg)

    known_macs = get_all_known_macs()
    for mac in known_macs:
        if mac not in online_macs:
            update_host_status(mac, False)


def start_scanning():
    """Main scanning loop that runs indefinitely based on SCAN_FREQUENCY."""
    with app.app_context():
        while True:
            active_hosts = run_ping_scan()

            # Get known MAC -> IP mapping from DB
            mac_ip_map = {host.mac: host.ip for host in Host.query.all()}

            # Determine hosts that are new or have changed IP
            hosts_to_scan = []
            for mac, ip in active_hosts:
                if mac not in mac_ip_map:
                    hosts_to_scan.append((mac, ip))  # new host
                elif ip != mac_ip_map[mac]:
                    hosts_to_scan.append((mac, ip))  # known MAC, new IP

            logging.info(
                f"Known MACs: {len(mac_ip_map)}, Active: {len(active_hosts)}, To Scan: {len(hosts_to_scan)}"
            )

            for mac, ip in hosts_to_scan:
                logging.info(f"Scanning host: {mac} - {ip}")
                run_full_scan(ip)

            logging.info(f"Sleeping for {SCAN_FREQUENCY} seconds...\n")
            sleep(SCAN_FREQUENCY)


if __name__ == "__main__":
    start_scanning()
