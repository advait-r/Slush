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

class BeaconTracker:
    """C2 beacons check in at regular intervals — low jitter between connection
    timestamps is the signature we're after, not any single packet's content."""

    def __init__(self, window_seconds=600, min_events=6):
        self.window = window_seconds
        self.min_events = min_events
        self.events = defaultdict(list)  # (src, dst, dst_port) -> [(ts, byte_count), ...]

    def record(self, src, dst, dst_port, ts, byte_count):
        key = (src, dst, dst_port)
        self.events[key].append((ts, byte_count))
        cutoff = ts - self.window
        self.events[key] = [e for e in self.events[key] if e[0] >= cutoff]

    def beacon_score(self, src, dst, dst_port):
        recs = self.events[(src, dst, dst_port)]
        if len(recs) < self.min_events:
            return None
        timestamps = [t for t, _ in recs]
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            return None
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / mean_interval   # coefficient of variation — low = regular
        return {
            "event_count": len(recs),
            "mean_interval": round(mean_interval, 2),
            "jitter_cv": round(cv, 3),
            "avg_bytes": round(sum(b for _, b in recs) / len(recs), 1),
        }
