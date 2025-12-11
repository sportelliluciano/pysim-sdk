import queue

from pysim_sdk.nic.events import Event, InterfaceEvent


class NicQueue(queue.Queue):
    # Number of events delivered
    total_events = 0

    def status(self):
        return {"totalEvents": self.total_events, "pendingEvents": self.qsize()}

    def events_stream(self, max_block_time=None):
        """
        Adapts a FIFO queue into an events generator.

        Maps interface events pushed from SpiInterface and WirelessInterface
        instances to a FIFO queue into Event/InterfaceEvent instances.

        To avoid blocking the main loop for too long this adapter will generate
        a synthetic `Tick` event if no other events arrive for longer than one
        second. You can control that interval with the `max_block_time` parameter.

        Note that it's not guaranteed that a `Tick` event will be generated every
        second. The only guarantee is that you will receive at least one event
        (of any kind) every one second. Do not use it to keep track of time.
        """
        while True:
            try:
                element = self.get(block=True, timeout=max_block_time)
                if not element:
                    break
                iface, event_name, payload = element
                if event_name == "packet-received":
                    self.total_events += 1
                    yield Event(InterfaceEvent.PacketReceived, payload, iface)
                elif event_name == "peer-connected":
                    self.total_events += 1
                    yield Event(InterfaceEvent.PeerConnected, payload, iface)
                elif event_name == "peer-lost":
                    self.total_events += 1
                    yield Event(InterfaceEvent.PeerLost, payload, iface)
                else:
                    raise NotImplementedError
            except queue.Empty:
                yield Event(InterfaceEvent.Tick, None, None)
