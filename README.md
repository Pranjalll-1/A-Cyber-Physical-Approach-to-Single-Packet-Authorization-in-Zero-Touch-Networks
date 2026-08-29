# A Cyber-Physical Approach to Single Packet Authorization in Zero-Touch Networks

## Abstract

Mission-critical networks require robust cybersecurity without the burden of heavy device patching. While Single Packet Authorization (SPA) effectively conceals network ports, purely software-based SPA remains vulnerable to stolen digital keys. Furthermore, automated Zero-Touch Networks (ZTNs) are highly susceptible to Adversarial Machine Learning (AML) manipulation.

To achieve strict micro-segmentation and "never trust" principles, we propose a Cyber-Physical Single Packet Authorization (CP-SPA) framework. This system requires a verifiable physical action—a dual-sensor "knock" at an edge controller—to dispatch an out-of-band authorization payload. An automated validation engine then dynamically updates the router’s Access Control List (ACL) to open a temporary micro-segment. By tying network authorization to a physical action, this framework neutralizes remote replay attacks, bypasses AML evasion, and establishes a highly resilient zero-trust perimeter.

## Project Architecture

- **Network Core:** Cisco 2911 Router and 2960 Switch establishing a local subnet.
- **Edge Controller:** A Single Board Computer (SBC) serving as the hardware authorization gate.
- **Cyber-Physical Sensors:** Push button and toggle switch acting as a dual-sensor physical "knock" mechanism.
- **Security Posture:** Default-deny Access Control List (ACL) blocking all remote access until physical verification is achieved.

## Progress Tracker

- **August 26, 2026 - Session 1: Network Foundation & Zero-Trust Perimeter**
  - Placed and wired all network devices and IoT sensors in Cisco Packet Tracer.
  - Configured static IPv4 addressing across the local subnet.
  - Generated 2048-bit RSA keys and locked down the central router with a strict `DENY ALL` ACL.
  - Verified baseline connectivity (Ping) and confirmed the firewall actively blocks unauthorized SSH attempts.

- **August 29, 2026 - Session 3: Hardware Authentication & Simulation Boundaries**
  * Finalized the Single Board Computer (SBC) logic gate, successfully mapping physical end-device interactions (Toggle Switch + Push Button) to logical outputs.
  * **Architectural Constraint Identified:** Cisco Packet Tracer's internal Python engine (Skulpt) restricts the execution of advanced networking libraries. Attempting to deploy the UDP payload generation resulted in: `NotImplementedError: socket is not yet implemented in Skulpt`.
  * **Review-1 Pivot & Strategy:** Due to the simulator's inability to compile raw network sockets, the physical LED on `D3` now acts as the visual proxy for the SPA payload dispatch. 
  * **Next Phase Roadmap:** While the Packet Tracer topology serves as the visual proof of the Cyber-Physical framework for Review-1, the final benchmarking phase (measuring resilience against Adversarial Machine Learning) will utilize an external Python environment to generate the necessary network packets and data graphs.
