import ipaddress
def subnet_to_prefix(subnet_mask):
    # Convert subnet mask to an IP address object
    subnet = ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)
    return subnet.prefixlen

class Interface:
    def __init__(self, interface: str, ip_address: str, subnet_mask: str):
        self.interface = interface
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask

    @property
    def prefix(self):
        return subnet_to_prefix(self.subnet_mask)

    def __repr__(self):
        return f"Interface {self.interface}], {self.ip_address}/{self.prefix}"