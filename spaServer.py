# brain of the router, sits dormant until it receives a perfect knock

import socket
import threading
import time
import json
import base64
import binascii
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import spaConfig as cfg


def debugPrint(status: str, msg: str) -> None:
    # Custom logger to format output cleanly
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {status} {msg}")


# Simulates the router's actual Access Control List (ACL)
class MockACL:

    def __init__(self) -> None:
        self._open_holes = set()
        self._lock = threading.Lock()

    # Adds client's IP to the allowed list and starts a background process
    def openPinhole(self, clientIp: str, duration: float) -> None:
        with self._lock:
            self._open_holes.add(clientIp)
        debugPrint("[+]", f"FIREWALL: Pinhole opened for {clientIp} ({duration:.0f}s)")

        timer = threading.Timer(duration, self._closePinhole, args=(clientIp,))
        timer.daemon = True
        timer.start()

    # ClosePinhole triggered automatically after 8 sec based on config file
    def _closePinhole(self, clientIp: str) -> None:
        with self._lock:
            self._open_holes.discard(clientIp)
        debugPrint("[-]", f"FIREWALL: Pinhole closed for {clientIp}. Default DROP restored.")

    def isOpen(self, clientIp: str) -> bool:
        with self._lock:
            return clientIp in self._open_holes


# Main Class
class SPAServer:
    
    def __init__(self, host: str, port: int, psk: bytes) -> None:
        self.host = host
        self.port = port
        self.aesgcm = AESGCM(psk)
        self.acl = MockACL()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Boots up the UDP socket and listens continuously 
    def start(self) -> None:
        self._sock.bind((self.host, self.port))
        debugPrint("[*]", f"ROUTER: Listening silently on {self.host}:{self.port}")
        
        try:
            while True:
                bytesRaw, addr = self._sock.recvfrom(4096)
                self._handlePacket(bytesRaw, addr)
        except KeyboardInterrupt:
            debugPrint("[!]", "ROUTER: Shutting down.")
        finally:
            self._sock.close()

    # Intercepts the raw bytes and send them down for decryption
    def _handlePacket(self, bytesRaw: bytes, addr: tuple) -> None:
        clientIp = addr[0]
        debugPrint("[*]", f"INBOUND: {len(bytesRaw)} bytes received from {clientIp} (Encrypted)")

        payload = self._decryptAndValidate(bytesRaw)

        if payload is None:
            debugPrint("[x]", f"ALERT: Invalid packet from {clientIp}. Dropping silently.")
            return

        debugPrint("[+]", f"AUTH: Decryption successful for device '{payload['client_id']}'")
        self.acl.openPinhole(clientIp, cfg.OPEN_DURATION)

    def _decryptAndValidate(self, raw_bytes: bytes):
        try:
            # Reversing the client side encryption
            envelope = base64.b64decode(raw_bytes)
            nonce = envelope[:cfg.NONCE_SIZE]
            ciphertext = envelope[cfg.NONCE_SIZE:]

            plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            payload = json.loads(plaintext.decode("utf-8"))

            # Integrity Checks 
            required_fields = {"client_id", "timestamp", "nonce", "gate"}
            if not required_fields.issubset(payload.keys()):
                debugPrint("[x]", "ERROR: Payload missing required keys. Discarding.")
                return None

            # If age > 5s => could be a replay attack => FLAG
            age = time.time() - float(payload["timestamp"])
            if age > cfg.MAX_PAYLOAD_AGE or age < -2:
                debugPrint("[x]", f"ALERT: Packet too old ({age:.2f}s). Possible replay attack blocked.")
                return None

            return payload

        except (InvalidTag, ValueError, KeyError, binascii.Error):
            return None


if __name__ == "__main__":
    server = SPAServer(cfg.SERVER_HOST, cfg.SPA_PORT, cfg.PRE_SHARED_KEY)
    server.start()