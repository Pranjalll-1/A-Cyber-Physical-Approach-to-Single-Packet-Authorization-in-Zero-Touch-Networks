#Trigger for the entire ZTN

import socket
import time
import json
import base64
import os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import spaConfig as cfg


def debugPrint(status: str, msg: str) -> None:
    # Custom logger to format output cleanly
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {status} {msg}")


#This simulates the edge controller's hardware mathematically
#takes 2 booleans push button high and toggle switch high
#isSatisfied functions acts as an AND logic gate and only returns true if both booleans are active simultaneously 
class PhysicalGate:

    def __init__(self, pushBtnHigh: bool, toggleSwHigh: bool) -> None:
        self.pushBtnHigh = pushBtnHigh
        self.toggleSwHigh = toggleSwHigh

    @property
    def isSatisfied(self) -> bool:
        return self.pushBtnHigh and self.toggleSwHigh

    def describe(self) -> str:
        # BUG FIX: Updated variable names to match __init__
        return (f"pushButton={'HIGH' if self.pushBtnHigh else 'LOW'}, "
                f"toggleSwitch={'HIGH' if self.toggleSwHigh else 'LOW'}")


class SPAClient:
    def __init__(self, serverHost: str, serverPort: int, psk: bytes,
                 clientId: str) -> None:
        self.serverHost = serverHost
        self.serverPort = serverPort
        self.aesgcm = AESGCM(psk)
        self.clientId = clientId

#The most imp function, takes the PhysicalGate obj and checks the status
#If gate returns false, the function returns immediately without doing any work 
    def tryKnock(self, gate: PhysicalGate) -> bool:
        debugPrint("[*]", f"GATE: Reading sensors -> {gate.describe()}")

        if not gate.isSatisfied:
            debugPrint("[x]", "GATE: Physical auth failed. Aborting payload generation.")
            return False

        debugPrint("[+]", "GATE: Hardware auth successful. Building secure payload.")
        self._sendKnock(gate)
        return True

    def _buildPayload(self, gate: PhysicalGate) -> dict:
        return {
            "client_id": self.clientId,
            "timestamp": time.time(),
            "nonce": os.urandom(8).hex(),
            "gate": gate.isSatisfied,
        }

#Payload is encrypted here so it can safely pass on a public network
    def _encrypt(self, payload: dict) -> bytes:
        plaintext = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(cfg.NONCE_SIZE)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data=None)
        envelope = nonce + ciphertext
        return base64.b64encode(envelope)

#opens a standard Python socket configured for AF_INET (IPv4) and SOCK_DGRAM (UDP)
    def _sendKnock(self, gate: PhysicalGate) -> None:
        payload = self._buildPayload(gate)
        wireBytes = self._encrypt(payload)

        debugPrint("[*]", f"BUILD: Payload ready for device '{payload['client_id']}'")
        debugPrint("[*]", f"ENCRYPT: AES-256-GCM envelope wrapped ({len(wireBytes)} bytes)")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(wireBytes, (self.serverHost, self.serverPort))

        debugPrint("[+]", f"TRANSMIT: UDP datagram fired to {self.serverHost}:{self.serverPort}")


if __name__ == "__main__":
    client = SPAClient(cfg.SERVER_HOST, cfg.SPA_PORT, cfg.PRE_SHARED_KEY,
                        clientId="edge-controller-01")

    demoGate = PhysicalGate(pushBtnHigh=True, toggleSwHigh=True)

    client.tryKnock(demoGate)