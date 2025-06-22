from scapy.all import sniff
import logging
import sys
import psutil

# Настройка логирования для модуля
logger = logging.getLogger(__name__)

def list_network_interfaces():
    """
    Список доступных сетевых интерфейсов.

    Использует библиотеку psutil для получения информации о сетевых интерфейсах
    устройства и возвращает список их имен.

    Returns:
        list: Список строк, содержащих имена сетевых интерфейсов.
    """
    interfaces = psutil.net_if_addrs()
    return [interface for interface in interfaces.keys()]

def choose_interface():
    """
    Выбор сетевого интерфейса пользователем.

    Отображает список доступных сетевых интерфейсов и позволяет пользователю
    выбрать один из них для захвата трафика. Если список интерфейсов пуст,
    программа завершится с ошибкой.

    Returns:
        str: Имя выбранного сетевого интерфейса.
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
    Захват сетевого трафика.

    Использует библиотеку Scapy для захвата пакетов на указанном интерфейсе.
    Пакеты фильтруются с помощью BPF-фильтра и анализируются с помощью переданного
    экземпляра TrafficAnalyzer. Захват продолжается до тех пор, пока не будет
    активировано событие остановки.

    Args:
        analyzer: Экземпляр класса TrafficAnalyzer для анализа пакетов.
        interface (str): Имя сетевого интерфейса для захвата трафика.
        bpf_filter (str): Строка с BPF-фильтром для применения к трафику.
        stop_event (Event): Объект события для управления остановкой захвата.

    Raises:
        Exception: Любая ошибка, возникшая во время захвата трафика, будет залогирована.
    """
    logger.info(f"Starting capture on {interface} with filter '{bpf_filter}'...")
    try:
        sniff(iface=interface, filter=bpf_filter, prn=analyzer.analyze_packet, stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        logger.error(f"An error occurred during traffic capture: {e}")
