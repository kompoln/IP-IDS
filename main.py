# Модуль захвата трафика
import pyshark
from win10toast import ToastNotifier
import psutil

def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return [interface for interface in interfaces]

def capture_traffic(interface=None, bpf_filter='tcp'):
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
        interface = interfaces[selected_idx]

    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    capture.sniff(timeout=50)
    return capture

# Модуль анализа трафика
import json
import re
filename = 'signatures.json'


class TrafficAnalyzer:
    def __init__(self, signatures_file=filename):
        self.signatures = self.load_signatures(signatures_file)

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
            for signature in self.signatures:
                protocol = packet.transport_layer
                dstport = packet[protocol].dstport if hasattr(packet[protocol], 'dstport') else None
                if protocol == signature['protocol'] and (dstport == str(signature['port']) or signature['port'] is None):
                    if signature['pattern'] is not None:
                        payload = packet.get_field_value('http.file_data') or packet.get_field_value('data.text')  # Примеры полей, которые могут содержать данные для анализа
                        if payload and re.search(signature['pattern'], payload):
                          return signature['name'], f"Attack detected based on signature: {signature['id']}"
                else:
                        # Для сигнатур без паттерна возможна другая логика обнаружения
                        pass
        except AttributeError:
            pass  # Не все пакеты содержат транспортный слой
        return None, None

    def analyze_traffic(self, capture):
        notifier = NotificationSender()
        for packet in capture:
            attack_name, message = self.analyze_packet(packet)
            if attack_name:
                print(message)
                notifier.send_notification("Security Alert", message)  # Отправка уведомления

# Модуль уведомлений

class NotificationSender:
    def __init__(self):
        self.toaster = ToastNotifier()

    def send_notification(self, title, message):
        self.toaster.show_toast(title, message, duration=10, threaded=True)

# Пример использования модуля уведомлений
if __name__ == "__main__":
    print("Starting the Intrusion Detection System...")
    try:
        captured_traffic = capture_traffic()
        if captured_traffic is not None:
            print("Traffic capture started on selected interface...")

        # Инициализируем анализатор трафика
        analyzer = TrafficAnalyzer()

        # Анализируем захваченный трафик
        analyzer.analyze_traffic(captured_traffic)
        print("Traffic analysis completed. Check the logs for any security alerts.")
    except Exception as e:
        print(f"An error occurred: {e}")