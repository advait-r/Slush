"""Standardized alert schema + sink for the read-only pipeline.
Nothing in this module ever writes back to a datapath — it only appends to a local file."""
from dataclasses import dataclass, asdict
import json


@dataclass
class Alert:
    timestamp: float
    flow_id: str
    src_ip: str
    dst_ip: str
    threat_class: str   # ddos | recon_scan | c2_beacon | dga_dns | dns_tunnel | encrypted_malware | exfiltration
    confidence: float    # 0-1
    severity: str         # low | medium | high | critical
    evidence: dict

    def to_json(self):
        return json.dumps(asdict(self))


class AlertSink:
    def __init__(self, path="alerts.jsonl"):
        self.path = path

    def emit(self, alert: Alert):
        with open(self.path, "a") as f:
            f.write(alert.to_json() + "\n")
