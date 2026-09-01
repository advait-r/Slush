"""DNS-based threat features: DGA domain detection and DNS-tunnelling detection.

Both read from the DNS query name only — no payload decryption, no probes, no lookups
of our own. Fits the read-only-enclave constraint the same way the rest of the
pipeline does.
"""
import math
from collections import Counter, defaultdict


def shannon_entropy(chars):
    if not chars:
        return 0.0
    counts = Counter(chars)
    total = len(chars)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def dns_query_features(qname: str) -> dict:
    """Per-query features. A single call of this is enough to flag likely DGA traffic —
    DGA domains are algorithmically generated, so they read as high-entropy, roughly
    domain-length strings with no linguistic structure (unlike a real word or brand).

    Also computes base_domain here (the last two labels, e.g. 'evil.example.com' ->
    'example.com') so the controller and TunnelTracker share one definition of it
    instead of each deriving it separately and risking drift.
    """
    qname = qname.rstrip(".")
    labels = qname.split(".")
    sld = labels[-2] if len(labels) >= 2 else qname
    base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname
    return {
        "qname": qname,
        "base_domain": base_domain,
        "qname_len": len(qname),
        "sld_entropy": shannon_entropy(list(sld)),
        "num_labels": len(labels),
        "digit_ratio": sum(c.isdigit() for c in sld) / max(len(sld), 1),
        "longest_label_len": max((len(l) for l in labels), default=0),
    }


class TunnelTracker:
    """DNS tunnelling (dnscat2, iodine, etc.) encodes data in frequent, long,
    high-entropy subdomain queries against the SAME base domain — that repetition and
    rate is the signal a single query's features can't show on its own.

    record() takes base_domain directly (computed once, in dns_query_features) rather
    than re-deriving it here — one source of truth, called out explicitly since a
    previous version of this class computed it twice and that mismatch is exactly
    what caused the KeyError bug this file fixes.
    """

    def __init__(self, window_seconds=30):
        self.window = window_seconds
        self.queries = defaultdict(list)   # (src, base_domain) -> [(ts, qname_len, entropy)]

    def record(self, src_ip: str, base_domain: str, ts: float, qname_len: int, entropy: float):
        key = (src_ip, base_domain)
        self.queries[key].append((ts, qname_len, entropy))
        cutoff = ts - self.window
        self.queries[key] = [q for q in self.queries[key] if q[0] >= cutoff]
        return base_domain

    def tunnel_score(self, src_ip: str, base_domain: str) -> dict:
        recs = self.queries.get((src_ip, base_domain), [])
        if not recs:
            return {"query_rate": 0.0, "avg_len": 0.0, "avg_entropy": 0.0, "count": 0}
        return {
            "query_rate": len(recs) / self.window,
            "avg_len": sum(r[1] for r in recs) / len(recs),
            "avg_entropy": sum(r[2] for r in recs) / len(recs),
            "count": len(recs),
        }
