#!/usr/bin/env python3
"""
Node A - sends/receives:
- Unencrypted message -> CAN ID 0x100
- Encrypted message (AES-128-ECB, PKCS7) -> CAN ID 0x101

Protocol (simple chunking):
Each CAN frame payload layout:
  byte 0 : msg_seq
  byte 1 : chunk_index
  byte 2 : total_chunks
  bytes 3..7 : payload chunk (up to 5 bytes)
"""

import can
import time
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import itertools

# ---------- Configuration ----------
CAN_INTERFACE = "vcan0"
UNENCRYPTED_ID = 0x100
ENCRYPTED_ID   = 0x101
ENCRYPTED_IDS  = [0x101, 0x201]

AES_KEY = b"1234567890abcdef"
AES_BLOCK = 16

SEND_INTERVAL = 1.0

# ---------- Globals ----------
bus = can.interface.Bus(channel=CAN_INTERFACE, bustype="socketcan")
seq_counter = itertools.count(1)
recv_assemblies = {}

assembly_lock = threading.Lock()

# ---------- AES Helpers ----------
def aes_encrypt_bytes(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES_BLOCK))

def aes_decrypt_bytes(ciphertext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK)

# ---------- CAN chunking helpers ----------
MAX_DATA_PER_FRAME = 5

def chunk_bytes_for_frames(data: bytes):
    return [data[i:i+MAX_DATA_PER_FRAME] for i in range(0, len(data), MAX_DATA_PER_FRAME)]

def send_chunks(can_id: int, raw_bytes: bytes):
    msg_seq = next(seq_counter) & 0xFF
    chunks = chunk_bytes_for_frames(raw_bytes)
    total_chunks = len(chunks) & 0xFF

    for idx, chunk in enumerate(chunks):
        data = bytearray(8)
        data[0] = msg_seq
        data[1] = idx & 0xFF
        data[2] = total_chunks
        data[3:3+len(chunk)] = chunk
        frame = can.Message(arbitration_id=can_id, data=bytes(data), is_extended_id=False)
        bus.send(frame)
        time.sleep(0.001)
    return msg_seq

# ---------- Sender ----------
def sender_loop():
    counter = 0
    while True:
        counter += 1

        plain_text = f"SPEED:{80 + (counter % 5)}"
        large_text = "FUEL_LEVEL:" + ("X" * (10 + (counter % 20)))

        plain_bytes = plain_text.encode()
        seq_plain = send_chunks(UNENCRYPTED_ID, plain_bytes)
        print(f"[SEND] UNENC id=0x{UNENCRYPTED_ID:X} seq={seq_plain} len={len(plain_bytes)} text={plain_text}")

        encrypted_bytes = aes_encrypt_bytes(large_text.encode())
        seq_enc = send_chunks(ENCRYPTED_ID, encrypted_bytes)
        print(f"[SEND] ENC   id=0x{ENCRYPTED_ID:X} seq={seq_enc} plaintext_len={len(large_text)} cipher_len={len(encrypted_bytes)}")

        time.sleep(SEND_INTERVAL)

# ---------- Reassembly ----------
def try_reassemble_and_process(can_id, msg_seq):
    key = (can_id, msg_seq)
    with assembly_lock:
        if key not in recv_assemblies:
            return
        entry = recv_assemblies[key]
        total = entry['total']
        chunks = entry['chunks']
        if len(chunks) != total:
            return

        assembled = bytearray()
        for i in range(total):
            assembled.extend(chunks[i])
        del recv_assemblies[key]

    if can_id in ENCRYPTED_IDS:
        try:
            dec = aes_decrypt_bytes(bytes(assembled))
            print(f"[RECV] ENC   id=0x{can_id:X} seq={msg_seq} decrypted_len={len(dec)} text={dec.decode(errors='replace')}")
        except Exception as e:
            print(f"[RECV] ENC   id=0x{can_id:X} seq={msg_seq} ERROR decrypt: {e}")
    else:
        try:
            txt = bytes(assembled).decode(errors='replace')
            print(f"[RECV] UNENC id=0x{can_id:X} seq={msg_seq} len={len(assembled)} text={txt}")
        except Exception as e:
            print(f"[RECV] UNENC id=0x{can_id:X} seq={msg_seq} ERROR decode: {e}")

# ---------- Receiver with SPOOF DETECTION ----------
def receiver_loop():
    valid_ids = [0x100, 0x101, 0x200, 0x201]

    for msg in bus:
        if msg is None or msg.data is None:
            continue

        data = msg.data
        if len(data) < 3:
            continue

        msg_seq = data[0]
        chunk_index = data[1]
        total_chunks = data[2]
        chunk_payload = bytes(data[3:8]).rstrip(b'\x00')

        # ---------------- SPOOF DETECTION ---------------- #
        # 1. Unknown CAN ID
        if msg.arbitration_id not in valid_ids:
            print(f"[SPOOF] Unknown CAN ID 0x{msg.arbitration_id:X}")
            continue

        # 2. total_chunks must be 1–20
        if total_chunks == 0 or total_chunks > 20:
            print(f"[SPOOF] Invalid total_chunks={total_chunks} id=0x{msg.arbitration_id:X} seq={msg_seq}")
            continue

        # 3. Invalid chunk index
        if chunk_index >= total_chunks:
            print(f"[SPOOF] chunk_index={chunk_index} out of range (total={total_chunks}) id=0x{msg.arbitration_id:X} seq={msg_seq}")
            continue

        # 4. Payload too long (>5 bytes)
        if len(chunk_payload) > 5:
            print(f"[SPOOF] Payload too long ({len(chunk_payload)}) id=0x{msg.arbitration_id:X}")
            continue

        # 5. Assembly consistency checks
        key = (msg.arbitration_id, msg_seq)
        with assembly_lock:
            stored = recv_assemblies.get(key)
            if stored:
                if stored['total'] != total_chunks:
                    print(f"[SPOOF] total_chunks changed old={stored['total']} new={total_chunks} id=0x{msg.arbitration_id:X}")
                    continue
                if chunk_index in stored['chunks']:
                    print(f"[SPOOF] Duplicate chunk_index={chunk_index} id=0x{msg.arbitration_id:X}")
                    continue

        # ---------------- Store chunk normally ---------------- #
        with assembly_lock:
            entry = recv_assemblies.get(key)
            if entry is None:
                recv_assemblies[key] = {'total': total_chunks, 'chunks': {}, 'last_time': time.time()}
                entry = recv_assemblies[key]
            entry['chunks'][chunk_index] = chunk_payload
            entry['last_time'] = time.time()

        try_reassemble_and_process(msg.arbitration_id, msg_seq)

# ---------- Cleanup ----------
def cleanup_loop(timeout=5):
    while True:
        now = time.time()
        with assembly_lock:
            stale = [k for k, v in recv_assemblies.items() if now - v['last_time'] > timeout]
            for k in stale:
                print(f"[CLEANUP] stale assembly removed: {k}")
                del recv_assemblies[k]
        time.sleep(1)

# ---------- Main ----------
if __name__ == "__main__":
    print("Node A starting. Interface:", CAN_INTERFACE)

    threading.Thread(target=receiver_loop, daemon=True).start()
    threading.Thread(target=cleanup_loop, daemon=True).start()

    try:
        sender_loop()
    except KeyboardInterrupt:
        print("Stopping Node A.")
