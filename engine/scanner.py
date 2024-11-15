from scapy.all import ARP, Ether, srp
import socket
import netifaces

from objetcs import (
    Interface
)

def scan_network(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and get the response
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def get_ip_and_subnet():
    interfaces = netifaces.interfaces()

    items = []
    for iface in interfaces:
        try:
            # Get the IP address and subnet mask
            iface_details = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            ip_address = iface_details['addr']
            subnet_mask = iface_details['netmask']

            items.append(
                Interface(interface=iface, ip_address=ip_address, subnet_mask=subnet_mask)
            )

        except (KeyError, IndexError):
            continue

    return items


if __name__ == "__main__":
    get_interfaces = get_ip_and_subnet()

    print(get_interfaces)