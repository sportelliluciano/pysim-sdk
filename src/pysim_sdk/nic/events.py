import enum


class Event:
    def __init__(self, kind, payload=None, src_if=None):
        self.type = kind
        self.src_if = src_if
        self.payload = payload


class InterfaceEvent(enum.Enum):
    Tick = 0
    PacketReceived = 1
    PeerConnected = 2
    PeerLost = 3
