import logging
import socket
import time
import json
import re
import psutil
import argparse
from collections import defaultdict
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import ARP

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

filename = 'signatures.json'

def list_network_interfaces():
    """
    Список всех доступных сетевых интерфейсов.
    :return: Список интерфейсов.
    """
    interfaces = psutil.net_if_addrs()
    return [interface for interface in interfaces]

def capture_traffic_scapy(interface=None, bpf_filter=None):
    """
    Захват сетевого трафика с помощью Scapy.
    :param interface: Сетевой интерфейс для захвата трафика.
    :param bpf_filter: Строка фильтра BPF.
    """
    if interface is None:
        interfaces = list_network_interfaces()
        if not interfaces:
            logger.error("No network interfaces available.")
            return None
        logger.info("Available network interfaces:")
        for idx, iface in enumerate(interfaces):
            logger.info(f"{idx}: {iface}")
        try:
            selected_idx = int(input("Select an interface by number (default 0): ") or "0")
        except ValueError:
            logger.error("Invalid input. Please enter a number.")
            return None
        if selected_idx < 0 or selected_idx >= len(interfaces):
            logger.error("Invalid interface number.")
            return None
        interface = interfaces[selected_idx]
    logger.info(f"Starting capture on {interface}...")
    sniff(iface=interface, filter=bpf_filter, prn=analyze_packet_scapy)

class TrafficAnalyzer:
    def __init__(self, signatures_file=filename):
        """
        Инициализация анализатора трафика.
        :param signatures_file: Путь к файлу с сигнатурами для обнаружения атак.
        """
        self.logger = logging.getLogger(__name__)
        self.logger.info('TrafficAnalyzer initialized with signatures from: ' + signatures_file)
        self.signatures = self.load_signatures(signatures_file)
        self.arp_monitor = defaultdict(lambda: {'hwsrc': None, 'count': 0})
        self.syn_flood_monitor = defaultdict(int)
        self.icmp_flood_monitor = defaultdict(int)
        self.last_time_checked = defaultdict(float)
        self.flood_threshold = 2000  # Порог для обнаружения Flood атак
        self.arp_poisoning_threshold = 5  # Порог для обнаружения ARP Spoofing
        self.local_ip = self.get_local_ip()  # Получение и сохранение локального IP-адреса
        self.port_scan_monitor = defaultdict(lambda: {'ports': set(), 'timestamp': time.time()})
        self.port_scan_threshold = 100  # Порог для обнаружения сканирования портов
        self.port_scan_time_window = 60  # Временное окно в секундах для обнаружения сканирования портов

        


    def get_local_ip(self):
        """
        Получение локального IP-адреса.
        :return: Локальный IP-адрес.
        """
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
        """
        Загрузка сигнатур из файла json.
        :param filename: Путь к файлу с сигнатурами.
        :return: Список сигнатур.
        """
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

    def check_for_flood(self, src_ip, monitor_dict, threshold):
        """
        Проверка на Flood атаку.
        """
        current_time = time.time()
        if current_time - self.last_time_checked[src_ip] > 1:
            self.last_time_checked[src_ip] = current_time
            monitor_dict[src_ip] = 0
        monitor_dict[src_ip] += 1
        if monitor_dict[src_ip] > threshold:
            return True
        return False
    

    def analyze_packet(self, packet):
        """
        Анализ пакета на предмет подозрительной активности на основе загруженного файла signatures.json.
        :param packet: Пакет для анализа.
        :return: Имя атаки и сообщение, если атака обнаружена.
        """
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Игнорируем пакеты, исходящие от локального IP-адреса
            if src_ip == self.local_ip:
                return None, None

            # Обнаружение ARP Spoofing
            if ARP in packet and packet[ARP].op == 2:  # ARP reply
                if self.arp_monitor[src_ip] and self.arp_monitor[src_ip] != packet[ARP].hwsrc:
                    self.arp_monitor[src_ip]['count'] += 1
                    if self.arp_monitor[src_ip]['count'] > self.arp_poisoning_threshold:
                        return "ARP Spoofing", f"ARP Spoofing detected from {src_ip}"
                else:
                    self.arp_monitor[src_ip] = {'hwsrc': packet[ARP].hwsrc, 'count': 1}

            # Обнаружение SYN Flood
            if TCP in packet and packet[TCP].flags == 'S':
                if self.check_for_flood(src_ip, self.syn_flood_monitor, self.flood_threshold):
                    return "SYN Flood", f"SYN Flood attack detected from {src_ip}"

            # Обнаружение ICMP Flood 
            if ICMP in packet:
                if self.check_for_flood(src_ip, self.icmp_flood_monitor, self.flood_threshold):
                    return "ICMP Flood", f"ICMP Flood attack detected from {src_ip}"

            # Обнаружение сканирования портов
            if TCP in packet or UDP in packet:
                self.detect_port_scan(packet, src_ip)

            # Обнаружение атаки на основе сигнатур
            for signature in self.signatures:
                if 'protocol' in signature and 'port' in signature:
                    protocol = signature['protocol']
                    port = int(signature['port'])

                    # Проверка соответствия протокола и порта
                    if (protocol == 'TCP' and TCP in packet and packet[TCP].dport == port) or \
                       (protocol == 'UDP' and UDP in packet and packet[UDP].dport == port):
                        payload = None
                        if protocol == 'TCP' and TCP in packet and 'load' in packet[TCP]:
                            payload = packet[TCP].load
                        elif protocol == 'UDP' and UDP in packet and 'load' in packet[UDP]:
                            payload = packet[UDP].load

                        if payload:
                            # Проверка соответствия паттерна сигнатуры
                            if re.search(signature['pattern'], payload.decode('utf-8', errors='ignore')):
                                return signature['name'], f"{signature['description']} from {src_ip}"
                else:
                    self.logger.error(f"Signature {signature.get('id', 'unknown')} is missing required keys 'protocol' or 'port'.")

        return None, None

    def detect_port_scan(self, packet, src_ip):
        """
        Обнаружение сканирования портов.
        :param packet: Пакет для анализа.
        :param src_ip: IP-адрес источника.
        """
        current_time = time.time()
        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport
        else:
            return

        # Обновляем информацию о сканировании портов
        if current_time - self.port_scan_monitor[src_ip]['timestamp'] > self.port_scan_time_window:
            # Если прошло больше времени, чем размер временного окна, сбросим данные
            self.port_scan_monitor[src_ip] = {'ports': set([port]), 'timestamp': current_time}
        else:
            # Добавляем порт в наблюдаемый набор и обновляем временную метку
            self.port_scan_monitor[src_ip]['ports'].add(port)
            self.port_scan_monitor[src_ip]['timestamp'] = current_time

            # Проверяем, превышено ли пороговое значение
            if len(self.port_scan_monitor[src_ip]['ports']) > self.port_scan_threshold:
                self.logger.warning(f"Port scan detected from {src_ip}. Ports: {self.port_scan_monitor[src_ip]['ports']}")
                # Сбросим данные после обнаружения сканирования портов
                self.port_scan_monitor[src_ip] = {'ports': set(), 'timestamp': current_time}




def analyze_packet_scapy(packet):
    #print(packet)
    """
    Передача пакета в TrafficAnalyzer для анализа.
    :param packet: Пакет для анализа.
    """
    if IP in packet:
        attack_name, message = analyzer.analyze_packet(packet)
        if attack_name:
            logger.info(message)
    else:
        logger.debug("Packet does not contain an IP layer.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Intrusion Detection System')
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture traffic on')
    parser.add_argument('-f', '--filter', type=str, default=None, help='BPF filter for capturing traffic')
    args = parser.parse_args()

    analyzer = TrafficAnalyzer()

    logger.info("Starting the Intrusion Detection System...")
    try:
        capture_traffic_scapy(interface=args.interface, bpf_filter=args.filter)
    except KeyboardInterrupt:
        logger.info("Intrusion Detection System stopped by user.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")