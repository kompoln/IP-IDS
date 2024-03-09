import logging
import socket
import time
import json
import re
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, ARP

# Класс для анализа трафика и обнаружения потенциальных атак
class TrafficAnalyzer:
    # Инициализация анализатора с загрузкой сигнатур из файла
    def __init__(self, signatures_file='signatures.json'):
        self.logger = logging.getLogger(__name__)
        self.logger.info('TrafficAnalyzer initialized with signatures from: ' + signatures_file)
        self.signatures = self.load_signatures(signatures_file)
        # Словарь для отслеживания ARP запросов и обнаружения ARP Spoofing
        self.arp_monitor = defaultdict(lambda: {'hwsrc': None, 'count': 0})
        # Словари для мониторинга SYN и ICMP Flood атак
        self.syn_flood_monitor = defaultdict(int)
        self.icmp_flood_monitor = defaultdict(int)
        # Время последней проверки для каждого IP
        self.last_time_checked = defaultdict(float)
        # Пороговые значения для обнаружения атак
        self.flood_threshold = 200
        self.arp_poisoning_threshold = 2
        # Получение локального IP адреса
        self.local_ip = self.get_local_ip()
        # Мониторинг сканирования портов
        self.port_scan_monitor = defaultdict(lambda: {'ports': set(), 'timestamp': time.time()})
        self.port_scan_threshold = 100
        self.port_scan_time_window = 60

    # Получение локального IP адреса
    def get_local_ip(self):
        # Создается временный сокет для определения локального IP адреса
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Попытка установить соединение с публичным DNS сервером (8.8.8.8)
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = '127.0.0.1'
        finally:
            s.close()
        return local_ip

     # Загрузка сигнатур из JSON файла
    def load_signatures(self, filename):
        # Попытка открыть файл сигнатур и загрузить его содержимое
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

    # Анализ пакетов на наличие подозрительной активности
    def analyze_packet(self, packet):
        # Обработка пакетов с IP заголовком
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            # Если пакет не содержит IP заголовок, он игнорируется
            return

        # Игнорирование пакетов, исходящих с локального IP адреса
        if src_ip == self.local_ip:
            return

        # Обработка ARP пакетов для обнаружения ARP Spoofing
        if ARP in packet and packet[ARP].op == 2:
            # Проверяем, изменился ли аппаратный адрес (MAC) для данного IP-адреса
            if self.arp_monitor[src_ip]['hwsrc'] and self.arp_monitor[src_ip]['hwsrc'] != packet[ARP].hwsrc:
                # Если MAC-адрес изменился, увеличиваем счетчик подозрительной активности
                self.arp_monitor[src_ip]['count'] += 1
                # Если счетчик превышает порог обнаружения ARP Spoofing, регистрируем предупреждение
                if self.arp_monitor[src_ip]['count'] > self.arp_poisoning_threshold:
                    self.logger.warning(f"ARP Spoofing detected from {src_ip}")
                    # Сбрасываем счетчик после обнаружения атаки
                    self.arp_monitor[src_ip]['count'] = 0
            else:
                # Если MAC-адрес не изменился или еще не был зарегистрирован, сохраняем текущий MAC-адрес
                self.arp_monitor[src_ip] = {'hwsrc': packet[ARP].hwsrc, 'count': 1}

        # Обработка TCP пакетов для обнаружения SYN Flood атак
        if TCP in packet and packet[TCP].flags == 'S':
            # Проверяем наличие чрезмерного количества SYN пакетов, что может указывать на SYN Flood
            if self.check_for_flood(src_ip, self.syn_flood_monitor, self.flood_threshold):
               self.logger.warning(f"SYN Flood attack detected from {src_ip}")
                # Сбрасываем счетчик после обнаружения атаки
               self.syn_flood_monitor[src_ip] = 0

        # Обработка ICMP пакетов для обнаружения ICMP Flood атак
        if ICMP in packet:
            # Проверяем наличие чрезмерного количества ICMP пакетов, что может указывать на ICMP Flood
            if self.check_for_flood(src_ip, self.icmp_flood_monitor, self.flood_threshold):
                self.logger.warning(f"ICMP Flood attack detected from {src_ip}")
                # Сбрасываем счетчик после обнаружения атаки
                self.icmp_flood_monitor[src_ip] = 0

        # Обработка TCP и UDP пакетов для обнаружения сканирования портов
        if TCP in packet or UDP in packet:
            # Вызываем метод для детектирования сканирования портов
            self.detect_port_scan(packet, src_ip)

        # Перебираем загруженные сигнатуры для обнаружения известных угроз
        for signature in self.signatures:
            # Проверяем, соответствует ли пакет сигнатуре по протоколу и порту
            if 'protocol' in signature and 'port' in signature:
                protocol = signature['protocol']
                port = int(signature['port'])

        # Проверяем TCP или UDP пакеты на соответствие порту из сигнатуры
        if (protocol == 'TCP' and TCP in packet and packet[TCP].dport == port) or \
           (protocol == 'UDP' and UDP in packet and packet[UDP].dport == port):
            payload = None
            # Извлекаем полезную нагрузку пакета для дальнейшего анализа
            if protocol == 'TCP' and TCP in packet and 'load' in packet[TCP]:
                payload = packet[TCP].load
            elif protocol == 'UDP' and UDP in packet and 'load' in packet[UDP]:
                payload = packet[UDP].load

            # Если в полезной нагрузке обнаружен паттерн из сигнатуры, регистрируем предупреждение
            if payload and re.search(signature['pattern'], payload.decode('utf-8', errors='ignore')):
                self.logger.warning(f"{signature['name']} from {src_ip}: {signature['description']}")
        
    def detect_port_scan(self, packet, src_ip):
        # Получаем текущее время для отметки времени пакета
        current_time = time.time()

        # Определяем порт назначения для TCP или UDP пакетов
        if TCP in packet:
            port = packet[TCP].dport
        elif UDP in packet:
            port = packet[UDP].dport
        else:
            # Если пакет не TCP/UDP, мы не обрабатываем его в этой функции
            return

        # Проверяем, превышено ли время ожидания для текущего источника сканирования
        if current_time - self.port_scan_monitor[src_ip]['timestamp'] > self.port_scan_time_window:
            # Если время ожидания превышено, начинаем новую сессию сканирования с текущим портом
            self.port_scan_monitor[src_ip] = {'ports': set([port]), 'timestamp': current_time}
        else:
            # Если время не превышено, добавляем порт в множество и обновляем время последнего пакета
            self.port_scan_monitor[src_ip]['ports'].add(port)
            self.port_scan_monitor[src_ip]['timestamp'] = current_time

            # Проверяем, превышено ли количество уникальных портов пороговое значение для сканирования
            if len(self.port_scan_monitor[src_ip]['ports']) > self.port_scan_threshold:
                # Если порог превышен, регистрируем предупреждение о сканировании портов
                self.logger.warning(f"Port scan detected from {src_ip}. Ports: {self.port_scan_monitor[src_ip]['ports']}")
                # Сбрасываем информацию о сканировании для данного IP
                self.port_scan_monitor[src_ip] = {'ports': set(), 'timestamp': current_time}

    def check_for_flood(self, src_ip, monitor_dict, threshold):
        # Получаем текущее время для сравнения с временем последней проверки
        current_time = time.time()
        # Проверяем, прошла ли секунда с момента последней проверки
        if current_time - self.last_time_checked[src_ip] > 1:
            # Если прошла, сбрасываем счетчик пакетов и время проверки
            self.last_time_checked[src_ip] = current_time
            monitor_dict[src_ip] = 0
        # Увеличиваем счетчик пакетов для данного IP
        monitor_dict[src_ip] += 1
        # Проверяем, превышено ли пороговое значение пакетов
        if monitor_dict[src_ip] > threshold:
            # Если порог превышен, возвращаем True (обнаружена потенциальная Flood атака)
            return True
        # Если порог не превышен, возвращаем False
        return False