# Intrusion Detection System (IDS)

## Overview

The Intrusion Detection System (IDS) is a Python-based tool designed to monitor network traffic and analyze packets for potential threats. It utilizes Scapy for capturing and analyzing packets and provides real-time alerts for any suspicious activities detected.

## Features

- **Traffic Analysis**: Capture and analyze network traffic in real-time.
- **Signature-Based Detection**: Utilize a JSON file with attack signatures for threat detection.
- **ARP Spoofing Detection**: Monitor ARP requests to identify ARP spoofing attempts.
- **SYN and ICMP Flood Detection**: Detect SYN and ICMP flood attacks based on threshold values.
- **Port Scanning Detection**: Identify port scanning activities by tracking the number of unique ports accessed within a time window.

## Usage

To run the IDS, use the following command:

```bash
python main.py [-i INTERFACE] [-f FILTER]
```

## Options:

- -i INTERFACE: Specify the network interface to capture traffic on (e.g., eth0).
- -f FILTER: Apply a BPF filter to the traffic capture (e.g., 'tcp port 80').

To stop the IDS, simply press q and Enter, or use Ctrl+C.

## Requirements
- Python 3.x
- Scapy
- Psutil
  
## Setup
1. Clone the repository to your local machine.
2. Install the required Python packages.
3. Run main.py with the desired options.

## Disclaimer
This project is designed for educational purposes and should not be used as a standalone security solution. Always use in conjunction with other security measures.

# Attack.py

## Overview

`attack.py` is a Python-based network attack simulator designed for educational and testing purposes. It allows users to perform various types of network attacks to understand their effects and to test the effectiveness of network defenses.

## Supported Attacks

- **SYN Flood**: Overloads a target server with TCP connection requests to exhaust its resources.
- **ICMP Flood**: Bombards the target with ICMP Echo Request messages to overwhelm the network.
- **ARP Spoofing**: Tricks the network into associating the attacker's MAC address with the IP address of another host.
- **Port Scanning**: Scans for open ports on the target system to identify potential attack vectors.

## Prerequisites

- Python 3.11
- Scapy library
- psutil library

## Usage

Run the script with Python 3, and follow the interactive prompts to select the attack type and specify target details:

```bash
python3 attack.py
```
## Disclaimer
This tool is for educational and testing purposes only. Use it responsibly and only on networks you have permission to test. Unauthorized use may be illegal.

## License
This project is licensed under the MIT License - see the LICENSE.txt file for details.

## Contribution
Contributions are welcome. Please open an issue or submit a pull request with your proposed changes or additions.
Acknowledgments
Thanks to the open-source community for the tools and libraries that made this project possible.


