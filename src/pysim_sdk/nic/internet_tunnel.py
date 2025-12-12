import socket
import struct
import select
import fcntl
import threading
import subprocess
import random

from scapy.all import raw, IP, ICMP, Ether, TCP, UDP, fragment
from scapy.layers.l2 import ARP

from pysim_sdk.nic.nic import BaseNetworkInterface
from pysim_sdk.utils import log
from pysim_sdk.utils.ip_address import str2ip


class InternetTunnel(BaseNetworkInterface):
    """
    Tunnels the virtual wireless interface to a real network interface card.

    This interface will listen on all incoming packets from the real NIC and
    will send all outgoing packets through the real NIC.
    """

    if_type = "inet"

    def __init__(self, events_sink, interface_name, layer_2=False, mtu=1500, nat_network="10.0.0.0", nat_mask="255.0.0.0"):
        self.events_sink = events_sink
        self._if_name = interface_name
        self._quit_signal = False
        self._thread = threading.Thread(target=self._main_thread, name="inet-tunnel")
        self.external_ip = None
        self.nat_table = None
        self.nat_network = nat_network
        self.nat_mask = nat_mask
        self.layer_2 = layer_2
        # Include IP and Ethernet headers 
        self.fragment_size = (mtu - (14 + 20)) if layer_2 else (mtu - 20)

    def _main_thread(self):
        with socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP
        ) as s, DisableTcpRstFromKernel():
            s.bind((self._if_name, 0x0800))
            self.external_ip = get_ip_address(self._if_name)
            self.ip_addr = self.external_ip
            self.mask = "255.255.255.255"
            self.nat_table = NAT(self.external_ip, self.nat_network, self.nat_mask)
            log.info("[INTERNET TUNNEL] external IP: %r", self.external_ip)
            self._socket = s
            while not self._quit_signal:
                rlist, *_ = select.select([s], [], [], 1)
                if not rlist:
                    continue

                raw_packet, _ = s.recvfrom(65536)
                packet = Ether(raw_packet)

                if IP in packet:
                    if nat_packet := self.nat_table.nat(packet[IP]):
                        log.info("[INTERNET TUNNEL] DISPATCH: %s - %r bytes", nat_packet, len(raw(nat_packet)))
                        self.count_packet_in(raw(nat_packet))
                        # Some NICs re-assemble packets on hardware before delivering them to 
                        # the kernel network stack. 
                        # This means that the stack can get packets that are bigger than the 
                        # link's MTU. For the simulation, we want to ensure packets put into
                        # simulated links respect the MTU, so we manually fragment them here. 
                        #
                        # See Generic Receive Offload (GRO) / Large Receive Offload (LRO)
                        fragments = fragment(nat_packet, fragsize=self.fragment_size)
                        for frag in fragments:
                            if self.layer_2:
                                self.events_sink.put(
                                    (self, "packet-received", raw(Ether() / frag))
                                )
                            else:  # Layer 3
                                self.events_sink.put(
                                    (self, "packet-received", raw(frag))
                                )
                else:
                    log.warn(f"[INTERNET TUNNEL] Filtering non-IP packet {packet}")
            self._socket = None

        log.info("Internet Tunnel thread finished")

    def enable_ap_mode(self, network, mask):
        self.events_sink.put((self, "peer-connected", None))

    def send_packet(self, packet: bytes):
        """
        Sends packet from node to tap device (home device)
        """
        if self.layer_2:
            packet = Ether(packet)
            if ARP in packet:
                self.handle_arp(packet)
                return

            if IP not in packet:
                log.warn(f"[INTERNET TUNNEL] Filtering out non-IP packet {packet}")
                return

            ip_packet = packet[IP]
        else:
            ip_packet = IP(packet)

        if ip_packet[IP].dst == "10.0.0.1":
            self.count_packet_out(ip_packet)
            self.handle_gateway_ip_datagram(ip_packet)
        elif self._socket:
            if nat_packet := self.nat_table.nat(ip_packet[IP]):
                log.info(f"[INTERNET TUNNEL] SEND: {nat_packet}")
                self.count_packet_out(nat_packet)
                self._socket.send(raw(Ether() / nat_packet))
            else:
                log.warn(f"[INTERNET TUNNEL] NAT filtered outgoing packet {ip_packet}")
        else:
            log.error(
                f"[INTERNET TUNNEL] Discarding {ip_packet} -- Tunnel not configured"
            )

    def __str__(self):
        return "inet-tunnel"

    def handle_gateway_ip_datagram(self, packet):
        log.info("[WLAN TUNNEL] virtual gateway: Got echo request from: %s", packet.dst)
        if ICMP in packet and packet[ICMP].type == 8:
            icmp_reply = packet[ICMP]
            icmp_reply.type = 0
            icmp_reply.code = 0
            icmp_reply.chksum = None
            reply = IP(dst=packet[IP].src, src=packet[IP].dst) / icmp_reply
            if self.layer_2:
                self.events_sink.put((self, "packet-received", raw(Ether() / reply)))
            else:
                self.events_sink.put((self, "packet-received", raw(reply)))
        else:
            log.warn(
                "[WLAN TUNNEL] virtual gateway: Unknown packet received: %s", packet
            )

    def handle_arp(self, eth_packet):
        """
        The node is an AP looking for a gateway among its stations.
        We need to return our mac when we hear an ARP request for 192.168.3.2
        """
        reply = Ether() / ARP(
            op=2,
            pdst=eth_packet[ARP].psrc,
            psrc=eth_packet[ARP].pdst,
            hwdst=eth_packet[ARP].hwsrc,
            hwsrc="aa:aa:11:00:00:00",
        )
        log.info(f"ARP handled: {eth_packet} ==> {reply}")
        self.events_sink.put((self, "packet-received", raw(reply)))

    def __enter__(self):
        assert not self._thread.is_alive(), "Internet Tunnel thread already started"
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._quit_signal = True
        self._thread.join()


# https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-from-a-nic-network-interface-controller-in-python
def get_ip_address(ifname):
    SIOCGIFADDR = 0x8915
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        return socket.inet_ntoa(
            fcntl.ioctl(
                s.fileno(),
                SIOCGIFADDR,
                struct.pack("256s", ifname[:15].encode("ascii")),
            )[20:24]
        )


class NAT:
    def __init__(self, external_ip, network, mask):
        self.external_ip = external_ip
        self.icmp_table = {}
        self.transport_nat_table = {}
        self.network = network
        self.mask = mask

    def nat(self, ip_packet):
        if ICMP in ip_packet:
            log.info(f"[NAT] ICMP NAT {ip_packet}")
            return self._do_icmp_nat(ip_packet)
        elif TCP in ip_packet or UDP in ip_packet:
            if result := self._do_transport_nat(ip_packet):
                log.info(f"[NAT] Transport NAT {ip_packet}")
                return result
            return None
        else:
            log.error(f"[NAT] unknown packet to nat: {ip_packet}")
            return None

    def _do_icmp_nat(self, ip_packet):
        if ip_packet[ICMP].type == 8:
            self.icmp_table[ip_packet[ICMP].id] = ip_packet[IP].src
            ip_packet[IP].src = self.external_ip
            ip_packet[IP].chksum = None
            ip_packet[ICMP].chksum = None
            return ip_packet
        elif ip_packet[ICMP].type == 0 and ip_packet[ICMP].id in self.icmp_table:
            ip_packet[IP].dst = self.icmp_table[ip_packet[ICMP].id]
            ip_packet[IP].chksum = None
            ip_packet[ICMP].chksum = None
            return ip_packet
        else:
            log.info(f"[NAT] Unknown ICMP nat: %s", ip_packet)
            return None

    def _do_transport_nat(self, ip_packet):
        protocol = TCP if TCP in ip_packet else UDP
        key = (
            protocol,
            ip_packet[IP].src,
            ip_packet[IP].dst,
            ip_packet[protocol].sport,
            ip_packet[protocol].dport,
        )

        if key not in self.transport_nat_table:
            if self._is_in_network(ip_packet[IP].src):
                log.info(f"[NAT] src is in root's network -- natting")
                self._create_transport_nat_entries(key)
            else:
                # log.error(
                #     f"[NAT] Dropping {ip_packet} -- not found in NAT table and not outgoing"
                # )
                return None

        _, srcip, dstip, sport, dport = self.transport_nat_table[key]
        log.info(f"[NAT] Resolution for {key}: {self.transport_nat_table[key]}")
        ip_packet[IP].src = srcip
        ip_packet[IP].dst = dstip
        ip_packet[IP].chksum = None
        ip_packet[protocol].sport = sport
        ip_packet[protocol].dport = dport
        ip_packet[protocol].chksum = None
        return ip_packet

    def _is_in_network(self, ip):
        return str2ip(ip) & str2ip(self.mask) == str2ip(self.network)

    def _create_transport_nat_entries(self, key):
        protocol, srcip, dstip, sport, dport = key
        # srcip -> external ip
        # sport -> generate port
        # rest unchanged
        # forward nat
        self.transport_nat_table[key] = (
            protocol,
            self.external_ip,
            dstip,
            sport,
            dport,
        )
        # backward nat
        self.transport_nat_table[(protocol, dstip, self.external_ip, dport, sport)] = (
            protocol,
            dstip,
            srcip,
            dport,
            sport,
        )

    def _generate_port(self):
        used_ports = []
        for entry in self.transport_nat_table:
            used_ports.append(entry[-2])

        for _ in range(10):
            port = random.randint(10000, 55000)
            if port not in used_ports:
                break

        if port in used_ports:
            log.error(f"[NAT] Cannot find free port for NAT")
            raise ValueError("No available ports")

        return port

    def __str__(self):
        return str(self.icmp_table) + "\n" + str(self.transport_nat_table)


class DisableTcpRstFromKernel:
    """
    This context manager will use iptables to drop any outgoing TCP-RST packet.

    This is needed for TCP to work inside nodes because the kernel will
    also receive any TCP traffic that's sent to us and since it's not
    the kernel the one handling TCP connections it will try to close it
    with an RST.

    NOTE: This requires NET_ADMIN and also iptables installed in the container.
    """

    def __enter__(self):
        subprocess.call("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP".split())

    def __exit__(self, _, __, ___):
        subprocess.call("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP".split())
