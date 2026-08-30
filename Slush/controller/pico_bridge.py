import sys
import time
import json
import serial
import os

if len(sys.argv) < 2:
    print("Usage: python3 pico_bridge.py <serial_port>")
    print("Example: python3 pico_bridge.py /dev/ttyACM1")
    sys.exit(1)

port = sys.argv[1]
baud_rate = 115200
alerts_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alerts.jsonl"))

# Configuration Settings
HEARTBEAT_INTERVAL = 2.0   # Send safe 0.00 score every 2s to keep Green LED awake
ATTACK_HOLD_TIME = 5.0     # How long to hold Yellow/Red state after an alert before going back to Green

try:
    pico = serial.Serial(port, baudrate=baud_rate, timeout=1)
    print(f"[+] Connected to Pico on {port}")
    time.sleep(2)

    print(f"[+] Watching {alerts_path} for live threat alerts...")
    print("[+] Emitting periodic heartbeat to keep Pico Green during benign traffic...\n")

    # Ensure alerts.jsonl exists
    if not os.path.exists(alerts_path):
        os.makedirs(os.path.dirname(alerts_path), exist_ok=True)
        open(alerts_path, 'a').close()

    with open(alerts_path, "r") as f:
        # Seek to the end of the file to catch live alerts only
        f.seek(0, os.SEEK_END)

        last_heartbeat = 0
        active_threat_until = 0

        while True:
            now = time.time()
            line = f.readline()

            if line:
                line_str = line.strip()
                if line_str:
                    try:
                        alert = json.loads(line_str)
                        threat_class = alert.get("threat_class", "benign")
                        confidence = float(alert.get("confidence", 0.0))
                        evidence = alert.get("evidence", {})

                        # Extract anomaly score or confidence
                        score = float(evidence.get("anomaly_score", confidence))

                        # Map scores for main.py thresholds:
                        # - < 0.60  -> Green LED
                        # - 0.60-0.94 -> Yellow LED + 1s Beep
                        # - >= 0.95 -> Red LED + Continuous Alarm
                        if threat_class == "benign":
                            score = 0.00
                        elif threat_class == "recon_scan" and score >= 0.95:
                            score = 0.75  # Cap scan alerts to trigger Yellow LED

                        # If an actual attack occurs, extend the active threat timer
                        if score >= 0.60:
                            active_threat_until = now + ATTACK_HOLD_TIME

                        payload = f"{score:.2f}\n"

                        pico.write(payload.encode('utf-8'))
                        pico.flush()
                        last_heartbeat = now
                        print(f"[Bridge Output -> Pico]: THREAT ALERT! [{threat_class}] Score={score:.2f}")

                    except (json.JSONDecodeError, ValueError):
                        pass  # Skip incomplete lines written during active logging

            else:
                # If no active threat is occurring and heartbeat timer expires, refresh Green safe state
                if now > active_threat_until and (now - last_heartbeat >= HEARTBEAT_INTERVAL):
                    try:
                        pico.write(b"0.00\n")
                        pico.flush()
                        last_heartbeat = now
                    except serial.SerialException as write_err:
                        print(f"[!] Write failed ({write_err}). Attempting to reconnect...")
                        time.sleep(1)
                        pico.close()
                        pico.open()

                time.sleep(0.05)

except serial.SerialException as e:
    print(f"[-] Serial Connection Error: {e}")
    print("[-] Tip: Close Thonny and run 'sudo chmod 666 /dev/ttyACM1'")
except KeyboardInterrupt:
    print("\n[+] Exiting pico_bridge.py...")
finally:
    if 'pico' in locals() and pico.is_open:
        pico.close()
