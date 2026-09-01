#This file simulate an Adverse Machine Learning (AML) attack

import base64
import json
import os
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import spaConfig as cfg
from spaServer import SPAServer                  
from spaClient import SPAClient, PhysicalGate   

STANDARD_NETWORK_PORT = cfg.SPA_PORT
CP_SPA_NETWORK_PORT = cfg.SPA_PORT + 1

SERVER_WARMUP_SECONDS = 0.3  
ACL_CHECK_DELAY_SECONDS = 0.3  

def simPrint(symbol: str, message: str) -> None:
    """Custom human-readable print function matching Phase 4 styling."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{symbol}] {message}")

@dataclass
class AttackResult:
    networkType: str        
    success: bool               
    ttb: float # Time to breach in seconds 
    reason: str

# This simulates that the attacker already has access to the AES-256 key
# IMP - This assumes that the attacker is attacking remotely and does not have access to physical buttons
class AdversarialML_Attacker:

    def __init__(self, stolenKey: bytes, mlConfidence: float = 0.997) -> None:
        self.stolenKey = stolenKey
        self.mlConfidence = mlConfidence
        self._aesgcm = AESGCM(self.stolenKey)

    # This scenario demonstrates how standard SPA networks fail during an attack
    def attackStandardSPA(self, targetPort: int, verifyWith: SPAServer) -> AttackResult:
        simPrint("*", "TARGET: Standard SPA Network (Software-only auth)")
        simPrint("!", f"MALWARE: Injecting scraped AES-256 key (Confidence: {self.mlConfidence:.1%})")

        start = time.perf_counter()

        forgedPayload = {
            "clientId": "edge-controller-01", 
            "timestamp": time.time(),
            "nonce": os.urandom(8).hex(),
            "gate": True,  # THE_HACK
        }
        simPrint("*", f"MALWARE: Forging payload for '{forgedPayload['clientId']}'")

        wireBytes = self._encrypt(forgedPayload)
        simPrint("*", f"MALWARE: Wrapping with AES-GCM envelope ({len(wireBytes)} bytes)")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(wireBytes, (cfg.SERVER_HOST, targetPort))
        simPrint("+", f"MALWARE: Firing UDP datagram to {cfg.SERVER_HOST}:{targetPort}")

        time.sleep(ACL_CHECK_DELAY_SECONDS)
        breached = verifyWith.acl.isOpen(cfg.SERVER_HOST)
        elapsed = time.perf_counter() - start

        if breached:
            simPrint("x", f"COMPROMISE: ACL pinhole opened! Firewall breached in {elapsed * 1000:.2f} ms")
        else:
            simPrint("-", "ATTACK FAILED: ACL remained closed.")

        return AttackResult(
            networkType="Standard-SPA",
            success=breached,
            ttb=elapsed,
            reason="Stolen digital key alone is sufficient to spoof network authorization.",
        )

    # How an AML attack behaves against our architecture 
    def attackCpSPA(self, targetPort: int, verifyWith: SPAServer) -> AttackResult:
        simPrint("*", "TARGET: CP-SPA Network (Hardware-gated auth)")
        simPrint("!", f"MALWARE: Injecting scraped AES-256 key (Confidence: {self.mlConfidence:.1%})")

        start = time.perf_counter()

        compromisedClient = SPAClient(cfg.SERVER_HOST, targetPort,
                                     self.stolenKey,
                                     clientId="edge-controller-01")

        attackerGate = PhysicalGate(pushBtnHigh=False, toggleSwHigh=False)
        simPrint("*", "MALWARE: Hijacking local client process to force payload generation...")

        packetSent = compromisedClient.tryKnock(attackerGate)

        time.sleep(ACL_CHECK_DELAY_SECONDS)
        isBreached = verifyWith.acl.isOpen(cfg.SERVER_HOST)
        timeElapsed = time.perf_counter() - start

        if not packetSent and not isBreached:
            simPrint("+", f"DEFENDED: Hardware gate blocked payload generation. Key rendered useless ({timeElapsed * 1000:.2f} ms)")

        return AttackResult(
            networkType="CP-SPA",
            success=isBreached,
            ttb=timeElapsed,
            reason=(
                "Physical gate evaluated False; payload generation hard-blocked."
                if not isBreached else
                "Physical gate was satisfied (unexpected in this threat model)."
            ),
        )

    def _encrypt(self, payload: dict) -> bytes:
        plaintext = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(cfg.NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data=None) 
        return base64.b64encode(nonce + ciphertext)

def _launchLiveServer(port: int) -> SPAServer:
    server = SPAServer(cfg.SERVER_HOST, port, cfg.PRE_SHARED_KEY)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    return server

def runComparison() -> None:
    print("\n" + "=" * 75)
    print(" PHASE 5: ADVERSARIAL ML ATTACK SIMULATION ")
    print("=" * 75)

    simPrint("*", "SETUP: Launching dual independent firewalls (Ports 9999 & 10000)")
    standardServer = _launchLiveServer(STANDARD_NETWORK_PORT)
    cpSpaServer = _launchLiveServer(CP_SPA_NETWORK_PORT)
    time.sleep(SERVER_WARMUP_SECONDS)

    attacker = AdversarialML_Attacker(stolenKey=cfg.PRE_SHARED_KEY)

    print("\n--- SCENARIO A: Software-Only SPA -----------------------------------------")
    result_a = attacker.attackStandardSPA(STANDARD_NETWORK_PORT, standardServer)

    print("\n--- SCENARIO B: CP-SPA (Hardware-Gated) -----------------------------------")
    result_b = attacker.attackCpSPA(CP_SPA_NETWORK_PORT, cpSpaServer)

    print("\n" + "=" * 75)
    print(" SIMULATION RESULTS ")
    print("=" * 75)
    for result in (result_a, result_b):
        verdict = "[ BREACHED ]" if result.success else "[ DEFENDED ]"
        print(f" {result.networkType:<14} {verdict} (t={result.ttb * 1000:6.2f}ms) | {result.reason}")
    print("=" * 75 + "\n")

if __name__ == "__main__":
    runComparison()