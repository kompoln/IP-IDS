from scapy.all import sniff
import logging
import sys
import psutil

logger = logging.getLogger(__name__)

def list_network_interfaces():
    """
    Возвращает список доступных сетевых интерфейсов на машине.
    """
    interfaces = psutil.net_if_addrs()
    return [interface for interface in interfaces.keys()]

def choose_interface():
    """
    Позволяет пользователю выбрать сетевой интерфейс из списка доступных.
    Возвращает имя выбранного интерфейса.
    """
    interfaces = list_network_interfaces()
    if not interfaces:
        logger.error("No network interfaces found.")
        sys.exit(1)

    logger.info("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        logger.info(f"{idx}: {iface}")

    try:
        selected_idx = int(input("Select an interface by number (default 0): ") or "0")
        if selected_idx < 0 or selected_idx >= len(interfaces):
            raise ValueError("Selected interface index is out of range.")
        interface = interfaces[selected_idx]
    except ValueError as e:
        logger.error(f"Invalid input: {e}")
        sys.exit(1)

    return interface

def capture_traffic(analyzer, interface, bpf_filter, stop_event):
    """
    Запускает захват трафика на указанном сетевом интерфейсе с возможностью остановки.
    analyzer - экземпляр класса TrafficAnalyzer для анализа пакетов
    interface - имя сетевого интерфейса для захвата трафика
    bpf_filter - строка с BPF-фильтром для применения к захватываемому трафику
    stop_event - threading.Event() для остановки захвата
    """
    logger.info(f"Starting capture on {interface} with filter '{bpf_filter}'...")
    try:
        sniff(iface=interface, filter=bpf_filter, prn=analyzer.analyze_packet, stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        logger.error(f"An error occurred during traffic capture: {e}")
