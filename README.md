# Automotive CAN Security Labs

Hands-on automotive cybersecurity labs focusing on Controller Area Network (CAN)
communication, ECU simulation, encrypted payload handling, and active attack scenarios.

This repository demonstrates how ECUs exchange both encrypted and unencrypted CAN
messages, how common CAN attacks are performed, and how basic detection mechanisms
can identify spoofed or malformed frames.

> ⚠️ Educational use only – do NOT run on real vehicles.

---

## Architecture Overview

The lab consists of three main components connected over a virtual CAN interface (`vcan0`):

- **Node A** – ECU simulator (sender & receiver)
- **Node B** – ECU simulator (sender & receiver)
- **Attack Node** – CAN bus attacker

---

## Node A – ECU Simulator

**File:** `node_a.py`

**Features:**
- Sends unencrypted CAN messages (e.g., vehicle speed)
- Sends encrypted CAN messages using AES-128 (ECB + PKCS7)
- Implements custom multi-frame CAN chunking
- Reassembles received frames into full payloads
- Decrypts encrypted messages
- Detects spoofing and malformed frames:
  - Unknown CAN IDs
  - Invalid chunk indexes
  - Duplicate chunks
  - Malformed payload sizes
- Removes stale or incomplete message assemblies

---

## Node B – ECU Simulator

**File:** `node_b.py`

**Features:**
- Sends unencrypted temperature data
- Sends encrypted pressure data using AES-128
- Reassembles and processes messages from Node A
- Detects duplicate CAN chunks (spoofing attempt)
- Periodic sensor-like message transmission

---

## Attack Node – CAN Bus Attacker

**File:** `attack_node.py`

**Implemented Attacks:**
1. **CAN Sniffing**
   - Capture CAN frames
   - Filter by CAN ID
   - Save traffic to log files

2. **Denial of Service (DoS)**
   - Flood the CAN bus with high-frequency frames

3. **Spoofing Attack**
   - Inject forged CAN frames with arbitrary IDs and payloads

4. **Replay Attack**
   - Re-send previously captured CAN traffic from log files

---

## Tools & Technologies

- Python
- SocketCAN / vCAN
- python-can
- PyCryptodome (AES)
- Linux (Kali / Ubuntu)
- Wireshark

---

## How to Run

```bash
# Create virtual CAN interface
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Run Node A
python3 node_a.py

# Run Node B (new terminal)
python3 node_b.py

# Run Attack Node
python3 attack_node.py
```

---

## Security Concepts Demonstrated

- Lack of authentication in CAN networks
- Replay and spoofing vulnerabilities
- Bus flooding (DoS)
- Plaintext vs encrypted CAN payloads
- Importance of message validation

---

## Disclaimer

This project is for **educational and research purposes only**.
Do NOT deploy or test this code on real vehicles or production systems.
