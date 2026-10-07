"""
Simulates 1000 trials to measure the overhead of hardware-gated authorization.
Generates latency distributions, component breakdowns, and raw CSV data.
"""

import socket
import threading
import time
import os
import random
import csv
import json
import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# --- Global Config ---
TOTAL_TRIALS = 1000
LOOPBACK = "127.0.0.1"
STD_PORT = 7701
CP_PORT = 7702
TIMEOUT = 2.0

# 32-byte AES-256 key and 12-byte nonce
SHARED_SECRET = AESGCM.generate_key(bit_length=256)
NONCE_LEN = 12

# Simulated hardware delay for Raspberry Pi/SBC (0.5ms to 3ms)
HW_POLL_DELAY = (0.0005, 0.0030)

class MockRouter(threading.Thread):
    """Simple UDP listener that decrypts the SPA packet and sends a 1-byte ACK to measure network transit."""
    def __init__(self, port, key):
        super().__init__(daemon=True)
        self.port = port
        self.cipher = AESGCM(key)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LOOPBACK, self.port))
        self.active = True

    def run(self):
        while self.active:
            try:
                data, addr = self.sock.recvfrom(4096)
                nonce, msg = data[:NONCE_LEN], data[NONCE_LEN:]
                self.cipher.decrypt(nonce, msg, associated_data=None)
                self.sock.sendto(b"\x01", addr) # Send ACK on success
            except OSError:
                break
            except Exception:
                self.sock.sendto(b"\x00", addr) # Send NACK on failure

    def shutdown(self):
        self.active = False
        self.sock.close()

def eval_standard_spa(client, target_ip, cipher):
    """Baseline: Immediate AES-256-GCM encryption and transmission."""
    packet_data = json.dumps({
        "client": "edge-node",
        "ts": time.time(),
        "nonce": os.urandom(8).hex()
    }).encode("utf-8")

    # Measure Crypto
    start_crypto = time.perf_counter()
    iv = os.urandom(NONCE_LEN)
    encrypted_payload = cipher.encrypt(iv, packet_data, associated_data=None)
    payload_to_send = iv + encrypted_payload
    dur_crypto = time.perf_counter() - start_crypto

    # Measure Network
    start_net = time.perf_counter()
    client.sendto(payload_to_send, target_ip)
    client.recvfrom(64)
    dur_net = time.perf_counter() - start_net

    return {"type": "Standard", "gpio": 0.0, "crypto": dur_crypto, "network": dur_net}

def eval_cp_spa(client, target_ip, cipher, ecdsa_key):
    """CP-SPA: Hardware delay -> ECDSA Sign + AES Encrypt -> transmission."""
    # Measure Hardware Polling
    dur_gpio = random.uniform(*HW_POLL_DELAY)
    time.sleep(dur_gpio) 

    packet_data = json.dumps({
        "client": "edge-node",
        "ts": time.time(),
        "nonce": os.urandom(8).hex(),
        "gate": True
    }).encode("utf-8")

    # Measure Crypto (AES + ECDSA Signature)
    start_crypto = time.perf_counter()
    iv = os.urandom(NONCE_LEN)
    encrypted_payload = cipher.encrypt(iv, packet_data, associated_data=None)
    hw_signature = ecdsa_key.sign(b"gate_state:HIGH", ec.ECDSA(hashes.SHA256()))
    payload_to_send = iv + encrypted_payload
    dur_crypto = time.perf_counter() - start_crypto

    # Measure Network 
    start_net = time.perf_counter()
    client.sendto(payload_to_send, target_ip)
    client.recvfrom(64)
    dur_net = time.perf_counter() - start_net

    return {"type": "CP-SPA", "gpio": dur_gpio, "crypto": dur_crypto, "network": dur_net}

def generate_visuals(data_list):
    """Plots the matplotlib graphs based on the trial data."""
    print("\n[*] Generating Data Visualizations...")
    
    std_total = [ (d["crypto"] + d["network"]) * 1000 for d in data_list if d["type"] == "Standard" ]
    cp_total = [ (d["gpio"] + d["crypto"] + d["network"]) * 1000 for d in data_list if d["type"] == "CP-SPA" ]
    
    cp_g = [ d["gpio"] * 1000 for d in data_list if d["type"] == "CP-SPA" ]
    cp_c = [ d["crypto"] * 1000 for d in data_list if d["type"] == "CP-SPA" ]
    cp_n = [ d["network"] * 1000 for d in data_list if d["type"] == "CP-SPA" ]

    # 1. Total Latency Boxplot
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.boxplot([std_total, cp_total], tick_labels=["Standard SPA", "CP-SPA (Hardware)"], patch_artist=True)
    ax.set_ylabel("Latency (ms)")
    ax.set_title(f"End-to-End Latency Comparison (N={TOTAL_TRIALS})")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.savefig("fig1_latency_boxplot.png", dpi=300)
    plt.close()

    # 2. CP-SPA Component Breakdown
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.boxplot([cp_g, cp_c, cp_n], tick_labels=["Hardware Polling", "Crypto (AES+ECDSA)", "Network Transit"], patch_artist=True)
    ax.set_ylabel("Latency (ms)")
    ax.set_title(f"CP-SPA Execution Breakdown (N={TOTAL_TRIALS})")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.savefig("fig2_cpspa_breakdown.png", dpi=300)
    plt.close()

    # 3. Distribution Histograms
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(std_total, bins=40, alpha=0.6, label="Standard SPA", density=True)
    ax.hist(cp_total, bins=40, alpha=0.6, label="CP-SPA", density=True)
    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("Density")
    ax.set_title(f"Latency Distributions (N={TOTAL_TRIALS})")
    ax.legend()
    plt.savefig("fig3_latency_distribution.png", dpi=300)
    plt.close()

    print("[+] Exported 3 PNG graphs to current directory.")

def main():
    cipher_suite = AESGCM(SHARED_SECRET)
    tpm_key = ec.generate_private_key(ec.SECP256R1())

    router_std = MockRouter(STD_PORT, SHARED_SECRET)
    router_cp = MockRouter(CP_PORT, SHARED_SECRET)
    router_std.start()
    router_cp.start()
    
    time.sleep(0.5) # Allow sockets to bind

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(TIMEOUT)

    metrics = []

    print(f"[*] Starting {TOTAL_TRIALS} Standard SPA Trials...")
    for _ in range(TOTAL_TRIALS):
        metrics.append(eval_standard_spa(client, (LOOPBACK, STD_PORT), cipher_suite))

    print(f"[*] Starting {TOTAL_TRIALS} CP-SPA Trials...")
    for _ in range(TOTAL_TRIALS):
        metrics.append(eval_cp_spa(client, (LOOPBACK, CP_PORT), cipher_suite, tpm_key))

    router_std.shutdown()
    router_cp.shutdown()
    client.close()

    # Export CSV
    with open("phase6_metrics.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Protocol", "t_gpio_ms", "t_crypto_ms", "t_net_ms", "t_total_ms"])
        for m in metrics:
            writer.writerow([m["type"], m["gpio"]*1000, m["crypto"]*1000, m["network"]*1000, (m["gpio"]+m["crypto"]+m["network"])*1000])
    
    print("[+] Raw data exported to phase6_metrics.csv")
    generate_visuals(metrics)

if __name__ == "__main__":
    main()