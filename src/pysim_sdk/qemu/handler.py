import os
import queue
import struct
import socket
import tempfile

import subprocess
import threading

from typing import Optional

from pysim_sdk.utils import log
from pysim_sdk.nic.nic_queue import NicQueue


class QemuHandler:
    def __init__(
        self,
        pysim,
        flash_file="/build/qemu_flash.bin",
        efuse_file="/build/qemu_efuse.bin",
        qemu_path="/usr/bin/qemu-system-xtensa",
    ):
        self.uds_path = os.path.join(tempfile.mkdtemp(), "qemu.sock")
        self.pysim = pysim
        self.flash_file = flash_file
        self.efuse_file = efuse_file
        self.qemu_path = qemu_path
        self.cmd_handlers = {}
        self.queue = NicQueueWrapper(NicQueue())

    def command(self, command_id: int):
        def decorator(function):
            self.cmd_handlers[command_id] = function
            return function

        return decorator

    def publish_event(self, event_id, event_payload=b""):
        self.queue.put((event_id, event_payload))

    def run(self):
        return main(
            self.uds_path,
            self.pysim,
            self.cmd_handlers,
            self.queue,
            self.flash_file,
            self.efuse_file,
            self.qemu_path,
        )


def main(
    uds_path,
    pysim,
    command_handlers,
    events_queue,
    flash_file="/build/qemu_flash.bin",
    efuse_file="/build/qemu_efuse.bin",
    qemu_path="/usr/bin/qemu-system-xtensa",
):

    qemu_cmd = [
        qemu_path,
        "-M",
        "esp32",
        "-m",
        "4M",
        "-drive",
        f"file={flash_file},if=mtd,format=raw",
        "-drive",
        f"file={efuse_file},if=none,format=raw,id=efuse",
        "-global",
        "driver=nvram.esp32.efuse,property=drive,value=efuse",
        "-global",
        "driver=timer.esp32.timg,property=wdt_disable,value=true",
        "-nographic",
        "-serial",
        "mon:stdio",
        "-serial",
        f"unix:{uds_path}",
    ]

    logs_thread = None
    qemu = None

    is_polling = False

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s_listen:
            os.makedirs(os.path.dirname(uds_path), exist_ok=True)
            if os.path.exists(uds_path):
                os.remove(uds_path)
            s_listen.bind(uds_path)
            s_listen.listen(1)
            qemu = subprocess.Popen(
                qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            logs_thread = threading.Thread(target=_push_qemu_logs, args=(qemu.stdout,))
            logs_thread.start()
            peer, _ = s_listen.accept()

            poll_lock = threading.Lock()
            conn = QemuPipe(peer)

            while header := conn.read_command():
                cmd, payload = header

                with poll_lock:
                    if is_polling:  # Clear polling for new command
                        conn.write_response(0)
                        is_polling = False
                        pysim.event("poll_exit", result=0)

                if cmd == 0xF4:  # Enter long polling

                    def _long_poll_finish():
                        nonlocal is_polling

                        with poll_lock:
                            if is_polling:
                                conn.write_response(1)
                                is_polling = False
                                pysim.event("poll_exit", result=1)

                    is_polling = True
                    events_queue.notify_on_data(_long_poll_finish)
                    pysim.event("poll_start")
                elif cmd == 0xF5:  # Retrieve event
                    pysim.event("retrieve_event")
                    try:
                        event = events_queue.get(block=False)
                        if not event:
                            conn.write_response(0)

                        event_id, event_payload = event
                        conn.write_response(event_id, event_payload)
                    except queue.Empty:
                        conn.write_response(0)
                elif cmd in command_handlers:
                    command_handlers[cmd](conn, cmd, payload)
                else:
                    raise RuntimeError(f"Client sent unrecognized command: {cmd!r}")

            log.info("Connection closed")
    except KeyboardInterrupt:
        log.info("Graceful quit requested")
    finally:
        if os.path.exists(uds_path):
            os.remove(uds_path)

        if qemu:
            log.info("waiting for qemu to finish...")
            qemu.kill()
            qemu.communicate()

        if logs_thread:
            log.info("Waiting for qemu logs thread to finish")
            logs_thread.join()

    log.info(f"QEMU instance at {uds_path!r} finished")


class NicQueueWrapper:
    def __init__(self, nic_queue):
        self.nic_queue = nic_queue
        self.id = 0
        self._cb_on_data = None

    def put(self, element):
        self.id += 1
        self.nic_queue.put(element)

        if self._cb_on_data:
            self._cb_on_data()

    def get(self, *args, **kwargs):
        return self.nic_queue.get(*args, **kwargs)

    def status(self):
        return self.nic_queue.status()

    def notify_on_data(self, callback):
        self._cb_on_data = callback

        if not self.nic_queue.empty():
            self._cb_on_data()


def _push_qemu_logs(stdout_pipe):
    for line in stdout_pipe:
        line = line.decode("utf-8").rstrip()
        if line.startswith("I"):
            log.info(line)
        elif line.startswith("W"):
            log.warn(line)
        elif line.startswith("E"):
            log.error(line)
        else:
            log.info(line)


def read_exact(s, n: int) -> Optional[bytes]:
    result = b""

    while len(result) < n:
        new_data = s.recv(n - len(result))
        if not new_data:
            if not result:
                # No new commands sent, connection closed OK
                return None

            # Received a partial command before connection closed -> bug
            raise RuntimeError(f"Can't read_exact({n}): connection closed")

        result += new_data

    return result


class QemuPipe:
    def __init__(self, s_peer):
        self.s_peer = s_peer

    def read_command(self):
        header = read_exact(self.s_peer, 4)
        if not header:
            return None

        cmd_and_size = struct.unpack("<I", header)[0]
        cmd = cmd_and_size >> 24
        payload_size = cmd_and_size & 0x00FF_FFFF
        payload = read_exact(self.s_peer, payload_size)
        return cmd, payload

    def write_response(self, ret: int, data: Optional[bytes] = None):
        if not data:
            data = b""

        ret_value = ((ret & 0xFF) << 24) | len(data)
        self.s_peer.sendall(struct.pack("<I", ret_value) + data)
