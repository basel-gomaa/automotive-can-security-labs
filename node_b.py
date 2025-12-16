#!/usr/bin/env python3
"""
Node B - sends/receives:
- Unencrypted Temperature -> CAN ID 0x200
- Encrypted Pressure (AES-128-ECB) -> CAN ID 0x201
- Receives Node A messages on 0x100 (plain) and 0x101 (encrypted)
"""

import can
import time
import threading
import itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------- Configuration ----------
CAN_INTERFACE = "vcan0"

UNENC_RECV_ID = 0x100   # from Node A
ENC_RECV_ID   = 0x101   # from Node A

UNENC_SEND_ID = 0x200   # Node B unencrypted (TEMP)
ENC_SEND_ID   = 0x201   # Node B encrypted (PRESSURE)

AES_KEY   = b"1234567890abcdef"
AES_BLOCK = 16
SEND_INTERVAL = 1.0

# ---------- Globals ----------
bus = can.interface.Bus(channel=CAN_INTERFACE, bustype="socketcan")
seq_counter = itertools.count(1)
recv_assemblies = {}  
assembly_lock = threading.Lock()

# ---------- AES ----------
def aes_encrypt_bytes(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(plaintext, AES_BLOCK)
    return cipher.encrypt(padded)

def aes_decrypt_bytes(ciphertext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    pt_padded = cipher.decrypt(ciphertext)
    return unpad(pt_padded, AES_BLOCK)

# ---------- Chunking ----------
MAX_DATA_PER_FRAME = 5

def chunk_bytes_for_frames(data: bytes):
    return [data[i:i+MAX_DATA_PER_FRAME] for i in range(0, len(data), MAX_DATA_PER_FRAME)]

def send_chunks(can_id: int, raw_bytes: bytes):
    msg_seq = next(seq_counter) & 0xFF
    chunks = chunk_bytes_for_frames(raw_bytes)
    total_chunks = len(chunks)

    for idx, chunk in enumerate(chunks):
        data = bytearray(8)
        data[0] = msg_seq
        data[1] = idx
        data[2] = total_chunks
        data[3:3+len(chunk)] = chunk

        frame = can.Message(arbitration_id=can_id, data=bytes(data), is_extended_id=False)
        bus.send(frame)
        time.sleep(0.001)

    return msg_seq

# ---------- Processing ----------
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

    # ----- Type decode -----
    if can_id == ENC_RECV_ID:
        try:
            dec = aes_decrypt_bytes(bytes(assembled))
            print(f"[RECV] ENC FROM A id=0x{can_id:X} seq={msg_seq} text={dec.decode(errors='ignore')}")
        except Exception as e:
            print(f"[RECV] ENC ERROR: {e}")
    else:
        try:
            dec = bytes(assembled).decode(errors="ignore")
            print(f"[RECV] UNENC FROM A id=0x{can_id:X} seq={msg_seq} text={dec}")
        except:
            print("[RECV] UNENC DECODE ERROR")

# ---------- Receiver ----------
def receiver_loop():
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

        key = (msg.arbitration_id, msg_seq)

        with assembly_lock:
            # ---- SPOOF DETECTION ----
            if key in recv_assemblies and chunk_index in recv_assemblies[key]["chunks"]:
                print(f"[WARNING] SPOOF DETECTED id=0x{msg.arbitration_id:X} seq={msg_seq} chunk={chunk_index}")

            # create buffer if new
            if key not in recv_assemblies:
                recv_assemblies[key] = {"total": total_chunks, "chunks": {}, "last_time": time.time()}

            recv_assemblies[key]["chunks"][chunk_index] = chunk_payload
            recv_assemblies[key]["last_time"] = time.time()

        try_reassemble_and_process(msg.arbitration_id, msg_seq)

# ---------- Cleanup stale data ----------
def cleanup_loop(timeout=5.0):
    while True:
        now = time.time()
        with assembly_lock:
            stale = [k for k,v in recv_assemblies.items() if now - v["last_time"] > timeout]
            for k in stale:
                print(f"[CLEANUP] Removing stale assembly {k}")
                del recv_assemblies[k]
        time.sleep(1.0)

# ---------- Sender ----------
def sender_loop():
    counter = 0
    while True:
        counter += 1

        # ----- Unencrypted TEMP -----
        temp_val = 25.0 + (counter % 5)
        temp_txt = f"TEMP:{temp_val}"
        seq_un = send_chunks(UNENC_SEND_ID, temp_txt.encode())
        print(f"[SEND] UNENC TEMP id=0x{UNENC_SEND_ID:X} seq={seq_un} text={temp_txt}")

        # ----- Encrypted PRESSURE -----
        pressure_val = 101.3 + (counter % 10)
        press_txt = f"PRESSURE:{pressure_val}"

        encrypted = aes_encrypt_bytes(press_txt.encode())
        seq_en = send_chunks(ENC_SEND_ID, encrypted)

        print(f"[SEND] ENC PRESS id=0x{ENC_SEND_ID:X} seq={seq_en} plain_len={len(press_txt)} cipher_len={len(encrypted)}")

        time.sleep(SEND_INTERVAL)

# ---------- MAIN ----------
if __name__ == "__main__":
    print("Node B running on", CAN_INTERFACE)

    t1 = threading.Thread(target=receiver_loop, daemon=True)
    t2 = threading.Thread(target=cleanup_loop, daemon=True)

    t1.start()
    t2.start()

    try:
        sender_loop()
    except KeyboardInterrupt:
        print("Node B stopped.")
