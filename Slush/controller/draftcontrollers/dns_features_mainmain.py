from collections import Counter, defaultdict
import math

def shannon_entropy(chars):
    if not chars:
        return 0.0
    counts = Counter(chars)
    total = len(chars)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

def dns_query_features(qname: str) -> dict:
    labels = qname.strip(".").split(".")
    sld = labels[-2] if len(labels) >= 2 else qname
    # base_domain = last two labels (eTLD+1-ish). This is what tunnel traffic actually
    # shares across queries — the encoded-data subdomain in front of it changes on every
    # single query, so grouping by the FULL qname (the old behavior) put every query in
    # its own bucket of size 1 and the rate never had a chance to build up.
    base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname
    return {
        "qname_len": len(qname),
        "sld_entropy": shannon_entropy(list(sld)),
        "num_labels": len(labels),
        "digit_ratio": sum(c.isdigit() for c in sld) / max(len(sld), 1),
        "longest_label_len": max(len(l) for l in labels) if labels else 0,
        "base_domain": base_domain,
    }

class TunnelTracker:
    """dnscat2/iodine encode data in frequent, long, high-entropy subdomains — track rate, not just one query."""
    def __init__(self, window_seconds=30):
        self.window = window_seconds
        self.queries = defaultdict(list)   # (src, base_domain) -> [(ts, qname_len, entropy)]

    def record(self, src, base_domain, ts, qname_len, entropy):
        key = (src, base_domain)
        self.queries[key].append((ts, qname_len, entropy))
        cutoff = ts - self.window
        self.queries[key] = [q for q in self.queries[key] if q[0] >= cutoff]
        # BUG FIX: this used to fall through with no return, so callers doing
        # `base_domain = tracker.record(...)` always got None back and then scored
        # the wrong (empty) bucket in tunnel_score(). Always return the key we stored under.
        return base_domain

    def tunnel_score(self, src, base_domain):
        recs = self.queries[(src, base_domain)]
        if not recs:
            return {"query_rate": 0, "avg_len": 0, "avg_entropy": 0}
        return {
            "query_rate": len(recs) / self.window,
            "avg_len": sum(r[1] for r in recs) / len(recs),
            "avg_entropy": sum(r[2] for r in recs) / len(recs),
        }
