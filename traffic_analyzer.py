import logging
import socket
import time
import json
import re
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, ARP

class TrafficAnalyzer:
    def __init__(self, signatures_file='signatures.json'):
        self.logger = logging.getLogger(__name__)
        self.logger.info('TrafficAnalyzer initialized with signatures from: ' + signatures_file)
        self.signatures = self.load_signatures(signatures_file)
        self.arp_monitor = defaultdict(lambda: {'hwsrc': None, 'count': 0})
        self.syn_flood_monitor = defaultdict(int)
        self.icmp_flood_monitor = defaultdict(int)
        self.last_time_checked = defaultdict(float)
        self.flood_threshold = 2000
        self.arp_poisoning_threshold = 5
        self.local_ip = self.get_local_ip()
        self.port_scan_monitor = defaultdict(lambda: {'ports': set(), 'timestamp': time.time()})
        self.port_scan_threshold = 100
        self.port_scan_time_window = 60

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = '127.0.0.1'
        finally:
            s.close()
        return local_ip

    def load_signatures(self, filename):
        try:
            with open(filename, 'r') as file:
                signatures = json.load(file)
            self.logger.info('Signatures loaded successfully.')
            return signatures
        except FileNotFoundError:
            self.logger.error(f"File {filename} not found.")
            return []
        except json.JSONDecodeError:
            self.logger.error(f"Error decoding JSON from file {filename}.")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            return []

    def analyze_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            # Если в пакете нет IP, мы не можем его анализировать.
            return

        if src_ip == self.local_ip:
            return

        if ARP in packet and packet[ARP].op == 2:
            if self.arp_monitor[src_ip]['hwsrc'] and self.arp_monitor[src_ip]['hwsrc'] != packet[ARP].hwsrc:
                self.arp_monitor[src_ip]['count'] += 1
                if self.arp_monitor[src_ip]['count'] > self.arp_poisoning_threshold:
                    self.logger.warning(f"ARP Spoofing detected from {src_ip}")
                    self.arp_monitor[src_ip]['count'] = 0
            else:
                self.arp_monitor[src_ip] = {'hwsrc': packet[ARP].hwsrc, 'count': 1}

        if TCP in packet and packet[TCP].flags == 'S':
            if self.check_for_flood(src_ip, self.syn_flood_monitor, self.flood_threshold):
                self.logger.warning(f"SYN Flood attack detected from {src_ip}")
                self.syn_flood_monitor[src_ip] = 0

        if ICMP in packet:
            if self.check_for_flood(src_ip, self.icmp_flood_monitor, self.flood_threshold):
                self.logger.warning(f"ICMP Flood attack detected from {src_ip}")
                self.icmp_flood_monitor[src_ip] = 0

        if TCP in packet or UDP in packet:
            self.detect_port_scan(packet, src_ip)

        for signature in self.signatures:
            if 'protocol' in signature and 'port' in signature:
                protocol = signature['protocol']
                port = int(signature['port'])

                if (protocol == 'TCP' and TCP in packet and packet[TCP].dport == port) or \
                   (protocol == 'UDP' and UDP in packet and packet[UDP].dport == port):
                    payload = None
                    if protocol == 'TCP' and TCP in packet and 'load' in packet[TCP]:
                        payload = packet[TCP].load
                    elif protocol == 'UDP' and UDP in packet and 'load' in packet[UDP]:
                        payload = packet[UDP].load

                    if payload and re.search(signature['pattern'], payload.decode('utf-8', errors='ignore')):
                        self.logger.warning(f"{signature['name']} from {src_ip}: {signature['description']}")



    def detect_port_scan(self, packet, src_ip):
        current_time = time.time()
        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport
        else:
            return

        if current_time - self.port_scan_monitor[src_ip]['timestamp'] > self.port_scan_time_window:
            self.port_scan_monitor[src_ip] = {'ports': set([port]), 'timestamp': current_time}
        else:
            self.port_scan_monitor[src_ip]['ports'].add(port)
            self.port_scan_monitor[src_ip]['timestamp'] = current_time

            if len(self.port_scan_monitor[src_ip]['ports']) > self.port_scan_threshold:
                self.logger.warning(f"Port scan detected from {src_ip}. Ports: {self.port_scan_monitor[src_ip]['ports']}")
                self.port_scan_monitor[src_ip] = {'ports': set(), 'timestamp': current_time}

    def check_for_flood(self, src_ip, monitor_dict, threshold):
        current_time = time.time()
        if current_time - self.last_time_checked[src_ip] > 1:
            self.last_time_checked[src_ip] = current_time
            monitor_dict[src_ip] = 0
        monitor_dict[src_ip] += 1
        if monitor_dict[src_ip] > threshold:
            return True
        return False
