"""Shared feature-extraction helpers for the passive threat-intel pipeline."""
import math
from collections import Counter, defaultdict


def shannon_entropy(items):
    """Low entropy = traffic converging on one/few source IPs (single-source flood).
    High entropy = traffic spread across many source IPs (spoofed/reflected/distributed flood)."""
    if not items:
        return 0.0
    counts = Counter(items)
    total = len(items)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class ScanTracker:
    """Fan-out detector: one source touching many destination hosts/ports in a short window
    is the classic recon/port-scan signature. Fed from packet_in, not flow stats — OVS
    flow-stats replies only carry ipv4_src/ipv4_dst here, never port numbers."""

    def __init__(self, window_seconds=10):
        self.window = window_seconds
        self.events = defaultdict(list)   # src_ip -> [(ts, dst_ip, dst_port)]

    def record(self, src, dst, port, ts):
        self.events[src].append((ts, dst, port))
        cutoff = ts - self.window
        self.events[src] = [e for e in self.events[src] if e[0] >= cutoff]

    def fanout(self, src):
        recent = self.events[src]
        return {
            "unique_dst_hosts": len({d for _, d, _ in recent}),
            "unique_dst_ports": len({p for _, _, p in recent}),
            "events_in_window": len(recent),
        }
