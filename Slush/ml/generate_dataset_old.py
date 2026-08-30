import pandas as pd
import numpy as np
import random

def make_flow(is_attack):
    return {
        "src_ip": "10.0.0.3" if is_attack else f"10.0.0.{random.randint(1,3)}",
        "dst_ip": "10.0.0.4",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "packet_count": np.random.poisson(500 if is_attack else 20),
        "byte_count": np.random.poisson(60000 if is_attack else 1500),
        "flow_duration": np.random.exponential(0.5 if is_attack else 5),
        "label": 0 if is_attack else 1   # 1 = legitimate, 0 = malicious
    }

rows = [make_flow(is_attack=(i % 5 == 0)) for i in range(20000)]
df = pd.DataFrame(rows)
df.to_csv("dataset.csv", index=False)
print(df['label'].value_counts())
