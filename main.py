import logging
import argparse
from threading import Thread, Event
from traffic_analyzer import TrafficAnalyzer
from network_utils import choose_interface, capture_traffic

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Функция для ожидания команды выхода
def wait_for_exit_command(stop_event):
    try:
        while not stop_event.is_set():
            user_input = input()
            if user_input.lower() == 'q':
                logger.info("Exiting program...")
                stop_event.set()
    except (EOFError, KeyboardInterrupt):
        logger.info("Intrusion Detection System stopped by user.")
        stop_event.set()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Intrusion Detection System')
    parser.add_argument('-i', '--interface', type=str, help='Network interface to capture traffic on')
    parser.add_argument('-f', '--filter', type=str, default='', help='BPF filter for capturing traffic')
    args = parser.parse_args()

    analyzer = TrafficAnalyzer()
    stop_event = Event()

    interface = args.interface if args.interface else choose_interface()

    logger.info("Starting the Intrusion Detection System...")

    # Запуск потока для захвата трафика
    capture_thread = Thread(target=capture_traffic, args=(analyzer, interface, args.filter, stop_event))
    capture_thread.start()

    # Запуск потока для ожидания команды выхода
    exit_thread = Thread(target=wait_for_exit_command, args=(stop_event,))
    exit_thread.start()

    try:
        while capture_thread.is_alive():
            capture_thread.join(timeout=1)
    except KeyboardInterrupt:
        logger.info("Stopping the Intrusion Detection System...")
        stop_event.set()
        capture_thread.join()
        exit_thread.join()

    logger.info("Intrusion Detection System has been stopped.")
