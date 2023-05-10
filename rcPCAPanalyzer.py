import sys
import os
import socket
from scapy.all import *
import geocoder
import datetime
from collections import defaultdict
import pyshark
import numpy as np
from scapy.layers import http
from scapy.all import *
from scapy.layers.tls.all import TLS
from scapy.layers.inet import TCP
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


###########################################################################
# Find all IPs that the initial argument IP contacted
def find_contacted_ips(pcap_file, src_ip):
        contacted_ips = set()

        packets = rdpcap(pcap_file)
        for packet in packets:
                if IP in packet:
                        if packet[IP].src == src_ip:
                                contacted_ips.add(packet[IP].dst)
                        elif packet[IP].dst == src_ip:
                                contacted_ips.add(packet[IP].src)

        return contacted_ips


###########################################################################
# Do a DNS lookup on a given IP
def dns_lookup(ip_address):
        try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                return hostname
        except socket.herror:
                return "NoHostnameFound"


###########################################################################
# GeoLocate a given IP
def geolocate_ip(ip_address):
        location = geocoder.ip(ip_address)
        if location.ok:
                address = location.json.get('address', 'Unknown')
                org = location.json.get('org', 'Uknown')
                return address, org
        else:
                return None, None


###########################################################################
# Count the number of connections between the initial argument IP
# and every IP it connects to
def count_connections(pcap_file, src_ip, contacted_ip):
    num_connections = 0

    packets = rdpcap(pcap_file)
    for packet in packets:
        if IP in packet:
            if (packet[IP].src == src_ip and packet[IP].dst == contacted_ip) or \
               (packet[IP].src == contacted_ip and packet[IP].dst == src_ip):
                num_connections += 1

    return num_connections


###########################################################################
# Calculate total traffic volume between IPs
def calculate_traffic_volume(pcap_file, src_ip, contacted_ip):
        traffic_volume = 0

        packets = rdpcap(pcap_file)
        for packet in packets:
                if IP in packet:
                        if packet[IP].src == src_ip and packet[IP].dst == contacted_ip:
                                traffic_volume += len(packet)
                        elif packet[IP].src == contacted_ip and packet[IP].dst == src_ip:
                                traffic_volume += len(packet)

        return traffic_volume


###########################################################################
# Detects the use of incorrect protocol over a port. Ex HTTP over 22.
def catchBadPortProtocol(pcap_file, src_ip, contacted_ip):
    invalid_protocols = set()
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(IP) and (packet[IP].src == src_ip and packet[IP].dst == contacted_ip or packet[IP].src == contacted_ip and packet[IP].dst == src_ip):
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                # Check for incorrect protocol use on specific ports
                if packet.haslayer(http.HTTPRequest) and (src_port not in [80, 8080, 443] and dst_port not in [80, 8080, 443]):
                    invalid_protocols.add(src_port if packet[IP].src == src_ip else dst_port)
                if packet.haslayer(TLS) and (src_port not in [443, 8443] and dst_port not in [443, 8443]):
                    invalid_protocols.add(src_port if packet[IP].src == src_ip else dst_port)
                if b"SSH" in bytes(packet[TCP].payload) and (src_port != 22 and dst_port != 22):
                    invalid_protocols.add(src_port if packet[IP].src == src_ip else dst_port)

    if invalid_protocols:
        return "Invalid Protocol: " + ", ".join(str(port) for port in invalid_protocols)
    else:
        return "No Invalid Protocols"


###########################################################################
# Get a list of the TTL values of the packets exchanged between the source IP and the contacted IP
# Analyze the values for potential anomalies. The threshold number is used to determine how many
# standard deviations away from the mean TTL value is a particular connection. This tends
# to indicate a potential anomaly, although not always. Its a signal to suggest further analysis.
# The threshold value can be changed as needed depending on the nature of the traffic but 2 or 3 covers
# about 95% of cases.

def getIPttlAnomalies(pcap_file, src_ip, contacted_ip, threshold=2):
        ttl_values = []

        packets = rdpcap(pcap_file)
        for packet in packets:
                if IP in packet:
                        if (packet[IP].src == src_ip and packet[IP].dst == contacted_ip) or \
                           (packet[IP].src == contacted_ip and packet[IP].dst == src_ip):
                                ttl_values.append(packet[IP].ttl)

        if len(ttl_values) > 1:
                mean_ttl = np.mean(ttl_values)
                std_ttl = np.std(ttl_values)

                anomalous_ttl_values = [ttl for ttl in ttl_values if abs(ttl - mean_ttl) > threshold * std_ttl]
        else:
                anomalous_ttl_values = []

        return anomalous_ttl_values


###########################################################################
# Detects the potential use of DNS tunneling
def detect_dns_tunneling(pcap_file, src_ip, contacted_ip, threshold=5, time_window=1):
        dns_query_timestamps = []

        packets = rdpcap(pcap_file)
        for packet in packets:
                if IP in packet and DNS in packet:
                        if ((packet[IP].src == src_ip and packet[IP].dst == contacted_ip) or
                                (packet[IP].src == contacted_ip and packet[IP].dst == src_ip)):
                                if packet[DNS].qr == 0:  # DNS query
                                        dns_query_timestamps.append(packet.time)

        if len(dns_query_timestamps) < threshold:
                return "No DNS Tunneling Detected"

        dns_query_timestamps = np.array(dns_query_timestamps)
        time_diffs = np.diff(dns_query_timestamps)

        for i in range(len(time_diffs) - threshold + 1):
                if np.sum(time_diffs[i:i + threshold - 1]) <= time_window:
                        return "DNS Tunneling Detected"

        return "No DNS Tunneling Detected"


###########################################################################
# Detect Executables in network stream
def detect_executables(pcap_file, src_ip, contacted_ip):
        pe_signature = b'\x4D\x5A'  # MZ in ASCII
        elf_signature = b'\x7F\x45\x4C\x46'  # .ELF in ASCII

        packets = rdpcap(pcap_file)
        for packet in packets:
                if IP in packet and Raw in packet:
                        if ((packet[IP].src == src_ip and packet[IP].dst == contacted_ip) or
                                (packet[IP].src == contacted_ip and packet[IP].dst == src_ip)):
                                payload = packet[Raw].load
                                if pe_signature in payload or elf_signature in payload:
                                        return "Executable Detected"

        return "No Executable Detected"


###########################################################################
# Detect Shell commands
def detect_shell_commands(pcap_file, src_ip, contacted_ip):
        shell_commands = [
                b"cmd.exe", b"/bin/sh", b"/bin/bash",
                b"whoami", b"net user"
        ]

        packets = rdpcap(pcap_file)
        for packet in packets:
                if IP in packet and Raw in packet:
                        if ((packet[IP].src == src_ip and packet[IP].dst == contacted_ip) or
                                (packet[IP].src == contacted_ip and packet[IP].dst == src_ip)):
                                payload = packet[Raw].load.lower()
                                for command in shell_commands:
                                        if command in payload:
                                                return "Shell Command Detected"

        return "No Shell Command Detected"


###########################################################################
# Find periodic connections such as C2 beacons
# This needs work to detect a variety of different scenarios
# The threshold parameter can be adjusted to change detection sensitivity
# Smaller values are more sensitive to smaller variations. This affects false positives
def detect_periodicity(pcap_file, src_ip, contacted_ip, threshold=0.5):
    time_deltas = []

    packets = rdpcap(pcap_file)
    prev_timestamp = None

    for packet in packets:
        if IP in packet:
            if (packet[IP].src == src_ip and packet[IP].dst == contacted_ip) or \
               (packet[IP].src == contacted_ip and packet[IP].dst == src_ip):
                timestamp = packet.time

                if prev_timestamp is not None:
                    time_deltas.append(timestamp - prev_timestamp)

                prev_timestamp = timestamp

    if len(time_deltas) > 1:
        std_time_deltas = np.std(time_deltas)

        if std_time_deltas < threshold:
            mean_time_delta = np.mean(time_deltas)
            return f"Periodicity Detected: {mean_time_delta:.2f} seconds"
        else:
            return "No Periodicity Detected"
    else:
        return "No Periodicity Detected"


###########################################################################
# MAIN
def main(pcap_file, src_ip):
        contacted_ips = find_contacted_ips(pcap_file, src_ip)

        for ip in contacted_ips:
                dns_name = dns_lookup(ip)
                address, org = geolocate_ip(ip)
                connection_count = count_connections(pcap_file, src_ip, ip)
                total_traffic = calculate_traffic_volume(pcap_file, src_ip, ip)
                anomalous_ttl_value = getIPttlAnomalies(pcap_file, src_ip, ip)

                if len(anomalous_ttl_value) == 0:
                        anomaly = "No Anomaly"
                else:
                        anomaly = anomalous_ttl_value

                dns_tunneling_detection = detect_dns_tunneling(pcap_file, src_ip, ip)
                executable_detection = detect_executables(pcap_file, src_ip, ip)
                shell_command_detection = detect_shell_commands(pcap_file, src_ip, ip)
                bad_protocol_detection = catchBadPortProtocol(pcap_file, src_ip, ip)
                periodicity = detect_periodicity(pcap_file, src_ip, ip)

                # Output all the results pipe delimited to the screen
                print(f"{ip} | {dns_name} | {address} | {org} | {connection_count} | {total_traffic} | {anomaly} | {dns_tunneling_detection} | {executable_detection} | {shell_command_detection} | {bad_protocol_detection} | {periodicity}")


if __name__ == "__main__":
        if len(sys.argv) != 3:
                print("Usage: python dns_lookup_for_ips.py <pcap_file> <src_ip>")
                sys.exit()

        pcap_file = sys.argv[1]
        src_ip = sys.argv[2]

        if not os.path.exists(pcap_file):
                print(f"Error: File {pcap_file} not found")
                sys.exit()

        main(pcap_file, src_ip)
