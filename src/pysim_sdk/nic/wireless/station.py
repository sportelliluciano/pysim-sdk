import threading
import select
import struct
import socket
import time

from scapy.compat import raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from pysim_sdk.nic.nic import BaseNetworkInterface
from pysim_sdk.utils import log
from pysim_sdk.utils.ip_address import ip2str


class WirelessStation(BaseNetworkInterface):
    if_type = "sta"

    def __init__(
        self,
        if_name,
        events_queue,
        ssid,
        wlan_barrier=None,
        wlan_unlock=None,
        connect_delay=5,
        sockets_dir="/tmp/pysim/links",
        start_scanning=True,
        enabled=True,
    ):
        self.name = if_name
        self.events_queue = events_queue
        self.socket_path = f"{sockets_dir}/{ssid}"
        self.quit = False
        self.wlan_barrier = wlan_barrier
        self.wlan_unlock = wlan_unlock
        self.connect_delay = connect_delay
        self._thread = threading.Thread(target=self._main_thread, name=if_name)
        self._socket = None
        self.scan = start_scanning
        self.is_enabled = enabled

    def enable_ap_mode(self, network, mask):
        """
        In the real device, the interface can be both in AP and STA mode simultaneously.
        For the simulation, we manually decide who is an AP and who is a station, so we are ignoring
        this method here.
        """
        pass

    def send_packet(self, packet: bytes):
        # log.info(f"[STA NIC] Sending out {Ether(packet)}")
        if not isinstance(packet, bytes):
            raise RuntimeError

        if not self._socket or self.quit:
            ip_packet = Ether(packet)
            log.error(f"[WLAN] Discarding {ip_packet} -- Peer not connected")
            return

        self.count_packet_out(packet)
        try:
            self._socket.send(packet)
        except:
            log.error("Connection to wlan peer lost unexpectedly")

    def start_scanning(self):
        self.scan = True

    def __enter__(self):
        if self._thread.is_alive():
            raise ValueError("Thread is already running")

        self._thread.start()
        return self

    def _main_thread(self):
        if not self.wlan_barrier.is_set():
            log.info(
                f"{self}: LOCKED -- waiting for another interface to establish a connection"
            )
            self.wlan_barrier.wait()
            # Yes, this time.sleep is fixing the lack of proper synchronization between processes.
            # However:
            #  - Proper synchronization would require custom simulation logic in the routing
            #    core, and that's something that we specifically want to avoid.
            #  - This solution is simple, easy to understand, and, fundamentally, it works
            #  - It somewhat resembles the real case scenario where a node randomly connects; it's
            #    just triggered by some other condition.
            time.sleep(self.connect_delay)
            log.info(f"{self}: UNLOCKED -- returning normal operation")

        while not self.scan:
            time.sleep(1.5)

        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)

        while not self.quit:
            while not self.is_enabled:
                time.sleep(0.25)

            self._socket = None
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s_peer:
                if not self._connect_to_ap(s_peer):
                    if self.quit:
                        break  # graceful quit
                    continue  # Interface is disabled

                my_ip, my_mask, gateway = struct.unpack("!III", s_peer.recv(65535))

                self._socket = s_peer
                # Peer connection started
                self.ip_addr = ip2str(my_ip)
                self.mask = ip2str(my_mask)
                self.events_queue.put(
                    (self, "peer-connected", (my_ip, my_mask, gateway))
                )
                if self.wlan_unlock:
                    log.info(f"{self}: Unlocking next wlan")
                    self.wlan_unlock.set()

                # Peer loop: dispatch incoming packets
                self._dispatch_peer_packets(self._socket)

                # Peer connection lost or graceful quit requested
                self.ip_addr = "0.0.0.0"
                self.mask = "0.0.0.0"
                self.events_queue.put((self, "peer-lost", (my_ip, my_mask, gateway)))
                self._socket = None

    def _connect_to_ap(self, s_peer):
        while not self.quit and self.is_enabled:
            if s_peer.connect_ex(self.socket_path) == 0:
                return True

            # If failed, wait for one sec and try again
            time.sleep(1)
        return False

    def _dispatch_peer_packets(self, s_peer):
        while not self.quit and self.is_enabled:
            rlist, _, _ = select.select([s_peer], [], [], 1)
            if not rlist:
                continue

            try:
                data = s_peer.recv(65536)
                if not data:
                    s_peer.close()
                    break
            except:
                log.error("Connection to wlan peer lost unexpectedly")
                break

            self.count_packet_in(data)
            self.events_queue.put((self, "packet-received", data))
            # log.info(f"[STA NIC] Received {Ether(data)}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._thread.is_alive():
            self.quit = True
            self._thread.join()

        if self._socket:
            self._socket = None

    def __str__(self):
        return self.name
