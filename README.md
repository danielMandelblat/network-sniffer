Thanks for the clarification! Here's the updated `README.md` with the correct usage example reflecting your code:

---

# Network Device Scanner

A Python-based tool to discover devices on a network, including their IP addresses, MAC addresses, open ports, and their associated vendor information.

## Features
- **Network Scanning**: Scans devices connected to your network using ARP requests.
- **Port Scanning**: Scans open ports for each discovered device.
- **MAC Address Vendor Lookup**: Queries MAC address vendors via an API (MAC Vendors API) to identify the manufacturer.
- **Multi-threaded Port Scanning**: Optimized port scanning using threading for faster performance.

## Requirements
- Python 3.x
- `scapy`: For ARP requests and network packet crafting.
- `requests`: For querying the MAC address vendor API.
- `netifaces`: To obtain network interface details.

### Install Dependencies
Before running the script, ensure the required dependencies are installed:

```bash
pip install scapy requests netifaces
```

## Usage

To use the tool, simply run the following script:

```python
from network_sniffer import get_interfaces  # Adjust the import as needed

get_interfaces = get_interfaces()
for inet in get_interfaces:
    print(f"Scanning interface: {inet.ip_address_with_prefix}")
    devices = inet.scan_network(get_mac_address_vendor=True, scan_open_ports=True)
```

This script will:
- List all available network interfaces.
- Scan devices in the same network and identify open ports.
- Identify the vendor for each device based on the MAC address.

### Output:
For each discovered device, the tool will print:
- **IP Address**: The IP address of the device.
- **MAC Address**: The MAC address of the device.
- **Vendor**: The manufacturer/vendor of the device (if available).
- **Open Ports**: The list of open ports on the device.

## How It Works

### 1. **Subnet Mask to Prefix Conversion**:
The tool automatically converts subnet masks to CIDR prefix notation using the `subnet_to_prefix` function.

### 2. **ARP Request for Device Discovery**:
The tool uses ARP (Address Resolution Protocol) to discover devices within the subnet of the detected network interfaces.

### 3. **Open Port Scanning**:
The tool attempts to connect to ports on each discovered device in the specified port range (default is ports 1-1024). Multi-threading is used for faster performance.

### 4. **MAC Address Vendor Lookup**:
The first 3 bytes of the MAC address (OUI) are used to query the MAC Vendors API, which returns the vendor name (e.g., Apple, Cisco, etc.).

### 5. **Threading for Efficient Port Scanning**:
The port scan is done in multiple threads to speed up the process, especially for devices with many open ports.

## Example Output:
```
Scanning interface: 192.168.1.1/24
192.168.1.10 [00:14:22:01:23:45]
Port (22) is open on IP address (192.168.1.10)
Port (80) is open on IP address (192.168.1.10)
Vendor for MAC address (00:14:22:01:23:45): Apple Inc.
192.168.1.20 [00:1A:2B:3C:4D:5E]
Port (443) is open on IP address (192.168.1.20)
Vendor for MAC address (00:1A:2B:3C:4D:5E): Cisco Systems, Inc.
```

## Code Overview

### **Classes**:
- **Device**:
  - Represents a networked device with its IP, MAC, open ports, and vendor information.
  - Methods to scan for open ports and retrieve the MAC address vendor.

- **Interface**:
  - Represents a network interface (e.g., `eth0`, `wlan0`).
  - Scans the local network for devices using ARP requests.
  - Provides methods for logging and retrieving network information.

- **Network Functions**:
  - `get_interfaces()`: Detects available network interfaces.
  - `subnet_to_prefix()`: Converts subnet mask to CIDR prefix.

### **Scanning**:
- The `scan_network` method in the `Interface` class scans for devices using ARP.
- For each device, the MAC address is looked up to get the vendor, and open ports are scanned.

### **Threading**:
- Port scanning is done concurrently using Python's `Thread` class for better performance, especially when scanning multiple ports on multiple devices.

## Customization
- You can modify the port range or enable/disable MAC address vendor lookup by changing the arguments in the `scan_network` method.
- You can also adjust the network interface to scan by specifying a particular interface in `get_interfaces()`.

## License
This tool is provided under the MIT License. See [LICENSE](LICENSE) for more details.

## Author
- **Name**: Daniel Mandelblat
- **Email**: [danielmande@gmail.com](mailto:danielmande@gmail.com)

---

Let me know if you need further adjustments!