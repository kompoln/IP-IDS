# Модуль захвата трафика
import pyshark
import psutil
import collections
import json
import re
import time
import socket

filename = 'signatures.json'

def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return [interface for interface in interfaces]

def capture_traffic(interface=None, bpf_filter=None):
    if interface is None:
        interfaces = list_network_interfaces()
        if not interfaces:
            print("No network interfaces available.")
            return None
        print("Available network interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx}: {iface}")
        selected_idx = int(input("Select an interface by number (default 0): ") or "0")
        if selected_idx < 0 or selected_idx >= len(interfaces):
            print("Invalid interface number.")
            return None
        # Получаем имя интерфейса из списка доступных интерфейсов
        interface = list(interfaces)[selected_idx]


    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    print("Starting capture...")
    return capture


# Модуль анализа трафика
class TrafficAnalyzer:
    def __init__(self, signatures_file=filename):
        self.signatures = self.load_signatures(signatures_file)
        self.port_scan_activity = collections.defaultdict(lambda: collections.defaultdict(int))
        self.last_notification_time = collections.defaultdict(int)
        self.notification_interval = 5  # Уведомления не чаще, чем раз в 5 секунд
        self.local_ip = self.get_local_ip()
        self.ddos_threshold = 1000  # Порог для обнаружения DDoS атаки
        self.ip_packet_count = collections.defaultdict(int)

    def get_local_ip(self):
        # Получаем локальный IP-адрес
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Не нужно подключаться, достаточно выбрать любой адрес и порт
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
            print('Signatures loaded successfully.')
            return signatures
        except FileNotFoundError:
            print(f"File {filename} not found.")
            return []
        except json.JSONDecodeError:
            print(f"Error decoding JSON from file {filename}.")
            return []

    def analyze_packet(self, packet):
        try:
            src_ip = packet.ip.src
            # Игнорируем пакеты, исходящие от локального IP-адреса
            if src_ip == self.local_ip:
                return None, None
            # Обновляем счетчик пакетов для IP-адреса источника
            self.ip_packet_count[src_ip] += 1
            
            # Обнаружение потенциальной DDoS атаки
            if self.ip_packet_count[src_ip] > self.ddos_threshold:
                print(f"Potential DDoS attack detected from {src_ip}")
                # Сброс счетчика после обнаружения атаки
                self.ip_packet_count[src_ip] = 0

            # Обнаружение ICMP Echo Request (Ping)
            if packet.highest_layer == 'ICMP' and hasattr(packet.icmp, 'type') and packet.icmp.type == '8':
                return "Ping (ICMP Echo Request)", f"ICMP Echo Request detected from {src_ip}"

            for signature in self.signatures:
                protocol = packet.transport_layer
                dstport = packet[protocol].dstport if hasattr(packet[protocol], 'dstport') else None
                if protocol == signature['protocol'] and (dstport == str(signature['port']) or signature['port'] is None):
                    if signature['pattern'] is not None and hasattr(packet, 'http'):
                        payload = packet.http.file_data if hasattr(packet.http, 'file_data') else None
                        if payload and re.search(signature['pattern'], payload):
                            return signature['name'], f"Attack detected based on signature: {signature['id']}"

            # Обнаружение сканирования nmap
            if packet.transport_layer == 'TCP':
                dstport = packet.tcp.dstport
                self.port_scan_activity[src_ip][dstport] += 1
                current_time = time.time()
                if (len(self.port_scan_activity[src_ip]) > 100 and
                    (current_time - self.last_notification_time[src_ip] > self.notification_interval)):
                    self.last_notification_time[src_ip] = current_time
                    return "Nmap Scan", f"Potential nmap port scan detected from {src_ip}"
                
        except AttributeError:
            pass  # Не все пакеты содержат транспортный слой
        return None, None

    def analyze_traffic(self, capture):
        try:
            for packet in capture.sniff_continuously():
                attack_name, message = self.analyze_packet(packet)
                if attack_name:
                    print(message)
        except KeyboardInterrupt:
            print("Traffic analysis stopped by user.")


# Уведомления
if __name__ == "__main__":
    print("Starting the Intrusion Detection System...")
    try:
        captured_traffic = capture_traffic()
        if captured_traffic is not None:
            print("Traffic capture started on selected interface...")
            analyzer = TrafficAnalyzer()
            analyzer.analyze_traffic(captured_traffic)
    except KeyboardInterrupt:
        print("Intrusion Detection System stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")