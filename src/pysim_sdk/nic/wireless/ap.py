import contextlib
import os
import select
import socket
import struct
import threading
import time

from scapy.compat import raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from pysim_sdk.nic.nic import BaseNetworkInterface
from pysim_sdk.utils import log
from pysim_sdk.utils.ip_address import ip2str


class WirelessAp(BaseNetworkInterface):
    if_type = "ap"

    def __init__(
        self,
        if_name,
        events_queue,
        ssid=None,
        sockets_dir="/tmp/pysim/links",
        enabled=True,
    ):
        self.name = if_name
        self.events_queue = events_queue
        self.socket_path = f"{sockets_dir}/{ssid or if_name}"
        self.quit = False
        self._thread = threading.Thread(target=self._main_thread, name=if_name)
        self._socket = None
        self._network = None
        self._mask = None
        self.is_enabled = enabled

    def enable_ap_mode(self, network, mask):
        if self._thread.is_alive():
            assert (
                network == self._network and mask == self._mask
            ), f"Tried to re-enable AP mode with different network/mask"
            return

        self._network = network
        self._mask = mask
        self._thread.start()

    def start_scanning(self):
        raise RuntimeError("AP nics cannot start scanning networks")

    def send_packet(self, packet: bytes):
        # log.info(f"[AP NIC] Sending out {Ether(packet)}")
        if not isinstance(packet, bytes):
            raise RuntimeError

        if not self._socket or self.quit:
            ip_packet = Ether(packet)
            log.error(f"[WLAN] Discarding {ip_packet} -- Peer not connected")
            return

        try:
            self.count_packet_out(packet)
            self._socket.send(packet)
        except OSError as e:
            log.error(f"[WLAN-AP] Failed to send packet to peer: {e}")

    def __enter__(self):
        with contextlib.suppress(FileNotFoundError):
            os.remove(self.socket_path)

        return self

    def _main_thread(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s_listen:
            os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)
            s_listen.bind(self.socket_path)
            s_listen.listen(1)

            while not self.quit:
                while not self.is_enabled:
                    time.sleep(0.25)

                self.ip_addr = ip2str(self._network | 1)
                self.mask = ip2str(self._mask)

                # Accept peer incoming connection
                s_peer = self._wait_for_peer(s_listen)
                if not s_peer:
                    if self.quit:
                        break  # graceful quit
                    continue  # Interface is disabled

                with s_peer:
                    s_peer.sendall(
                        struct.pack(
                            "!III", self._network | 2, self._mask, self._network | 1
                        )
                    )
                    self._socket = s_peer

                    # Peer connection started
                    self.events_queue.put(
                        (
                            self,
                            "peer-connected",
                            (self._network | 1, self._mask, self._network | 2),
                        )
                    )

                    # Peer loop: dispatch incoming packets
                    self._dispatch_peer_packets(self._socket)

                    # Peer connection lost or graceful quit requested
                    self.events_queue.put(
                        (
                            self,
                            "peer-lost",
                            (self._network | 1, self._mask, self._network | 2),
                        )
                    )

                self._socket = None

    def _wait_for_peer(self, s_listen):
        while not self.quit and self.is_enabled:
            rlist, _, _ = select.select([s_listen], [], [], 1)
            if rlist:
                connection, _ = s_listen.accept()
                return connection
        return None

    def _dispatch_peer_packets(self, s_peer):
        while not self.quit and self.is_enabled:
            rlist, _, _ = select.select([s_peer], [], [], 1)
            if not rlist:
                continue

            data = s_peer.recv(65536)
            if not data:
                s_peer.close()
                break

            self.count_packet_in(data)
            self.events_queue.put((self, "packet-received", data))
            # log.info(f"[AP NIC] Received {Ether(data)}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._thread.is_alive():
            self.quit = True
            self._thread.join()

        with contextlib.suppress(FileNotFoundError):
            os.remove(self.socket_path)

        if self._socket:
            self._socket = None

    def __str__(self):
        return self.name
