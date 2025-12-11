class BaseNetworkInterface:
    packets_in = 0
    bytes_in = 0
    packets_out = 0
    bytes_out = 0
    ip_addr = "0.0.0.0"
    mask = "0.0.0.0"
    if_type = ""
    is_enabled = True

    def count_packet_in(self, packet: bytes):
        self.packets_in += 1
        self.bytes_in += len(packet)

    def count_packet_out(self, packet: bytes):
        self.packets_out += 1
        self.bytes_out += len(packet)

    def start_scanning(self):
        """
        Starts scanning and trying to connect to nearby networks
        """
        raise NotImplementedError

    def send_packet(self, ip_packet: bytes):
        """
        Sends a packet through the interface.
        """
        raise NotImplementedError

    def status(self):
        return {
            "name": str(self),
            "ip": self.ip_addr,
            "mask": self.mask,
            "packetsIn": self.packets_in,
            "packetsOut": self.packets_out,
            "bytesIn": self.bytes_in,
            "bytesOut": self.bytes_out,
            "if_type": self.if_type,
        }

    def enable(self):
        self.is_enabled = True

    def disable(self):
        self.is_enabled = False
