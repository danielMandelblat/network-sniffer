from scapy.all import ARP, Ether, srp
from threading import Thread
import socket
import netifaces
import ipaddress
import requests

def subnet_to_prefix(subnet_mask):
    # Convert subnet mask to an IP address object
    subnet = ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)
    return subnet.prefixlen

def get_interfaces(ignore_local=True):
    interfaces = netifaces.interfaces()

    items = []
    for iface in interfaces:
        try:
            # Get the IP address and subnet mask
            iface_details = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            ip_address = iface_details['addr']
            subnet_mask = iface_details['netmask']

            if not (ignore_local and ip_address.startswith("127.0.0")):
                items.append(
                    Interface(interface=iface, ip_address=ip_address, subnet_mask=subnet_mask)
                )

        except (KeyError, IndexError):
            continue

    return items

class Device:
    vendor = None
    open_ports = []

    # Class attribute
    vendors = {}

    def __init__(self, interface: object, ip: str, mac: str):
        self.interface = interface
        self.ip = ip
        self.mac = mac

    def __repr__(self):
        return f"{self.ip} [{self.mac}]"

    def scan_ports(self, as_thread = True, port_range=(1, 1024)):
        threads = []

        def scan(port):
            try:
                # Try to connect to the IP address on the port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Timeout after 1 second
                result = sock.connect_ex((self.ip, port))  # Returns 0 if the port is open

                if result == 0:
                    self.open_ports.append(port)
                    self.interface.logging(
                        f"Port ({port}) is open on IP address ({self.ip})"
                    )

                sock.close()
            except socket.error:
                ...
        # Iterate over the desired ports
        for port in range(port_range[0], port_range[1] + 1):
            if as_thread:
                t = Thread(target=scan, args=(port,))
                t.start()
                threads.append(t)
            else:
                scan(port)

        # Wait to all the threads to be finished
        if as_thread:
            for t in threads:
                t.join()

        return self.open_ports

    @classmethod
    def add_vendor(cls, vendor: str, mac: str) -> str:
        if mac not in cls.vendors:
            cls.vendors[mac] = vendor
        return cls.vendors[mac]

    @classmethod
    def get_vendor(cls, mac: str) -> str:
        if mac in cls.vendors:
            return cls.vendors[mac]

    @property
    def get_mac_vendor(self) -> str:
        if self.vendor == None:
            # Make sure the MAC address is in the correct format (remove hyphens or colons)
            mac_address = self.mac.replace(":", "").replace("-", "").upper()[:6]

            if mac_address in self.vendors:
                self.vendor = self.vendors[mac_address]
            else:
                # Query the API
                url = f"https://api.macvendors.com/{mac_address}"
                response = requests.get(url)
                if response.status_code == 200:
                    self.vendor = response.text  # The provider name
                else:
                    self.vendor = "Unknown provider"

                # Add new vendor
                self.add_vendor(vendor=self.vendor, mac=mac_address)

        return self.vendor

class Interface:
    devices = []
    console_process = True

    def __init__(self, interface: str, ip_address: str, subnet_mask: str):
        self.interface = interface
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask

    def logging(self, item: object):
        if self.console_process:
            print(item)

    @property
    def prefix(self) -> str:
        return subnet_to_prefix(self.subnet_mask)

    @property
    def ip_address_with_prefix(self) -> str:
        return f"{self.ip_address}/{self.prefix}"

    def scan_network(
            self,
            scan_open_ports: bool = True,
            get_mac_address_vendor=True,
    ) -> list:
        # Create an ARP request packet
        arp = ARP(pdst=self.ip_address_with_prefix)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send the packet and get the response
        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            device = Device(
                interface=self,
                ip=received.psrc,
                mac=received.hwsrc
            )
            self.logging(device)
            self.devices.append(device)

            # Get the vendor?
            if get_mac_address_vendor:
                device.get_mac_vendor

            # Get the open ports?
            if scan_open_ports:
                device.scan_ports()

        return self.devices

    def __repr__(self):
        return f"Interface {self.interface}], {self.ip_address_with_prefix}"


if __name__ == "__main__":
    get_interfaces = get_interfaces()
    for inet in get_interfaces:
        print(f"Scanning interface: {inet.ip_address_with_prefix}")
        devices = inet.scan_network(get_mac_address_vendor=True, scan_open_ports=True)