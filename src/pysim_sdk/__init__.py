import enum
import os
import threading
import time
import queue
import base64
import json
import sys

import requests


class PysimClient:
    def __init__(self, device_id=None, node_id=None, base_url="http://localhost:8080"):
        # We need an unique ID that is also resistant to container restarts.
        # HOSTNAME by default equals the container hash. As long as we don't
        # remove the container the container hash should stay the same.
        self._node_id = node_id or os.getenv("HOSTNAME")
        self._watch_target = None
        self._base_url = base_url
        self._device_id = device_id

        self._worker = Worker(
            self._w_on_event, self._w_on_tick, heartbeat_interval_secs=0.5
        )
        self._w_events_queue = []

    def _w_on_event(self, event):
        for attribute, value in event.get("data", {}).items():
            if isinstance(value, bytes):
                event["data"][attribute] = base64.b64encode(value).decode("utf-8")

        try:
            json.dumps(event)
        except TypeError as e:
            print(f"Cannot convert {event!r} to JSON: {e.args}", file=sys.stderr)
            return
        self._w_events_queue.append(event)

    def _w_on_tick(self):
        if self._w_events_queue:
            requests.post(
                f"{self._base_url}/nodes/{self._node_id}/events",
                json=self._w_events_queue,
            ).json()
            self._w_events_queue = []

            self._w_send_status_updates()

    def _w_send_status_updates(self):
        updates = [
            {
                "timestamp": time.time_ns(),
                "source": self._device_id,
                "stream": "status",
                "data": self._watch_target.status() if self._watch_target else {},
            }
        ]

        requests.post(
            f"{self._base_url}/nodes/{self._node_id}/status",
            json=updates,
        ).json()

    def is_pysim_ready(self):
        for _ in range(10):
            try:
                ret = requests.get(f"{self._base_url}/probe/healthy")
                if ret.status_code == 200:
                    return True
            except requests.exceptions.ConnectionError:
                pass  # Pysim not ready yet

            time.sleep(1)
        return False

    def __enter__(self):
        if not self.is_pysim_ready():
            raise Exception("Pysim not ready")

        self._worker.start()
        return self

    def get_config(self):
        result = requests.get(f"{self._base_url}/nodes/{self._node_id}/config").json()
        if "detail" in result:
            raise Exception(f"{result!r}")
        return result

    def watch(self, device):
        self._watch_target = device
        device.observer = self

    def event(self, name, **kwargs):
        self._send_event("events", {"event": name, **kwargs})

    def log(self, json_data: str):
        self._send_event(
            "logs",
            {
                "msg": json_data,
                "thread_name": threading.current_thread().name,
            },
        )

    def _send_event(self, stream, data):
        self._worker.send(
            {
                "timestamp": time.time_ns(),
                "stream": stream,
                "source": self._device_id,
                "data": data,
            }
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._worker.stop()


class Worker:
    def __init__(self, on_element, on_heartbeat, heartbeat_interval_secs=0.5):
        self._thread = threading.Thread(name="pysim", target=self._main)
        self._queue = WorkerQueue()

        self.heartbeat_interval_secs = heartbeat_interval_secs
        self.on_element = on_element
        self.on_heartbeat = on_heartbeat

    def start(self):
        self._thread.start()

    def _main(self):
        last_heartbeat_sent = time.monotonic()
        while event := self._queue.get_or_default(
            WorkerControl.Timeout, timeout=self.heartbeat_interval_secs
        ):
            if time.monotonic() - last_heartbeat_sent > self.heartbeat_interval_secs:
                self.on_heartbeat()
                last_heartbeat_sent = time.monotonic()

            if event == WorkerControl.Timeout:
                continue

            if event == WorkerControl.Quit:
                break

            self.on_element(event)

    def send(self, event):
        self._queue.put(event)

    def stop(self):
        self._queue.put(WorkerControl.Quit)
        self._thread.join()


class WorkerQueue(queue.Queue):
    def get_or_default(self, default, timeout=None):
        try:
            return self.get(block=True, timeout=timeout)
        except queue.Empty:
            return default


class WorkerControl(enum.Enum):
    Quit = 0
    Timeout = 1
