import pandas as pd
import numpy as np
import random

# label encoding: 0 = ddos (malicious), 1 = benign, 2 = exfiltration (malicious)
LABELS = {"ddos": 0, "benign": 1, "exfiltration": 2}


def make_flow(kind):
    if kind == "ddos":
        # many small/medium packets, high total volume, short-lived flow — matches your original params
        packet_count = np.random.poisson(500)
        byte_count = np.random.poisson(60000)
        flow_duration = np.random.exponential(0.5)
        src_ip = "10.0.0.3"
    elif kind == "exfiltration":
        # fewer packets but each carrying much more data, sustained over a longer connection —
        # this is the shape that a flow-count gate (tuned for "many flows") would miss
        packet_count = np.random.poisson(80)
        byte_count = np.random.poisson(500000)
        flow_duration = np.random.exponential(8)
        src_ip = f"10.0.0.{random.randint(1, 3)}"
    else:  # benign
        packet_count = np.random.poisson(20)
        byte_count = np.random.poisson(1500)
        flow_duration = np.random.exponential(5)
        src_ip = f"10.0.0.{random.randint(1, 3)}"

    packet_count = max(int(packet_count), 1)
    byte_count = max(int(byte_count), 1)
    flow_duration = max(float(flow_duration), 0.001)

    return {
        "src_ip": src_ip,
        "dst_ip": "10.0.0.4",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "flow_duration": flow_duration,
        "bytes_per_packet": byte_count / packet_count,   # NEW: strongest single separator for exfil
        "label": LABELS[kind],
    }


def pick_kind(i):
    r = i % 10
    if r < 2:       # 20% ddos
        return "ddos"
    elif r < 3:      # 10% exfiltration
        return "exfiltration"
    else:            # 70% benign
        return "benign"


rows = [make_flow(pick_kind(i)) for i in range(20000)]
df = pd.DataFrame(rows)
df.to_csv("dataset.csv", index=False)
print(df["label"].value_counts())
