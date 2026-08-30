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
alerts_path = os.path.join(os.path.dirname(__file__), "..", "alerts.jsonl")

try:
    pico = serial.Serial(port, baudrate=baud_rate, timeout=1)
    print(f"[+] Successfully connected to Pico on {port}")
    time.sleep(2)  # Wait for serial connection to settle

    print(f"[+] Watching {alerts_path} for live threat alerts...")
    print("[+] Press Ctrl+C to stop.\n")

    # Ensure alerts file exists before tailing
    if not os.path.exists(alerts_path):
        open(alerts_path, 'a').close()

    with open(alerts_path, "r") as f:
        # Move to the end of the file to only catch new live alerts
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)  # Poll interval for new log lines
                continue
            
            line_str = line.strip()
            if not line_str:
                continue

            try:
                alert = json.loads(line_str)
                threat_class = alert.get("threat_class", "benign")
                confidence = alert.get("confidence", 0.0)

                # Map threat types to a score scale for your Pico
                score = confidence if threat_class == "ddos" else 0.0

                # Attempt writing to Pico with error resilience
                try:
                    pico.write(f"{score:.2f}\n".encode('utf-8'))
                    pico.flush()
                    print(f"[Bridge Output -> Pico]: Threat={threat_class}, Score={score:.2f}")
                except serial.SerialException as write_err:
                    print(f"[!] Write failed ({write_err}). Attempting to reconnect...")
                    time.sleep(1)
                    pico.close()
                    pico.open()

            except json.JSONDecodeError:
                pass  # Skip incomplete lines written mid-poll

except serial.SerialException as e:
    print(f"[-] Serial Connection Error: {e}")
    print("[-] Tip: Make sure Thonny is closed, run 'sudo chmod 666 /dev/ttyACM1', and stop ModemManager.")
except KeyboardInterrupt:
    print("\n[+] Exiting pico_bridge.py...")
finally:
    if 'pico' in locals() and pico.is_open:
        pico.close()
