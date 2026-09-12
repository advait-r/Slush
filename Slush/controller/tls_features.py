"""TLS ClientHello/ServerHello fingerprinting (JA3/JA3S) for the read-only enclave.

Parses only handshake metadata (cipher suites, extensions, curves) — never touches
Application Data, never decrypts anything. The handshake is sent in cleartext by the
TLS protocol before any encryption keys are negotiated, so nothing here is decryption
at all; this is the same "reads what's already plaintext" argument as dns_features.py.

Known limitation, stated honestly rather than glossed over: this parses a ClientHello/
ServerHello that arrives whole in a single TCP payload, which is true for the vast
majority of real-world handshakes (a few hundred bytes, well under typical MTU) but
will silently miss a handshake that a middlebox or unusual client fragments across
multiple segments. Reassembly across packet_in events would need TCP stream tracking
this pipeline doesn't otherwise do — flag this as a stated scope limit in the report,
the same way the accuracy caveat is stated for the RF.
"""
import hashlib
import struct
from collections import defaultdict

# GREASE values (RFC 8701) — TLS clients/servers insert these fake, meaningless values
# on purpose to force interop with implementations that don't choke on unknown values.
# Real JA3 excludes them, or the same client produces a different fingerprint on every
# connection, which defeats fingerprinting entirely.
GREASE_VALUES = frozenset([
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
])

TLS_HANDSHAKE_CONTENT_TYPE = 0x16
CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02


def _is_grease(value):
    return value in GREASE_VALUES


def _parse_extensions(data, offset, end):
    """Returns (ext_types, curves, point_formats) from a ClientHello/ServerHello
    extensions block. curves/point_formats only ever come back non-empty for a
    ClientHello — ServerHello doesn't carry supported_groups or ec_point_formats."""
    ext_types, curves, point_formats = [], [], []
    while offset + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        ext_data = data[offset:offset + ext_len]
        if not _is_grease(ext_type):
            ext_types.append(ext_type)
        if ext_type == 10 and len(ext_data) >= 2:          # supported_groups (curves)
            list_len = struct.unpack("!H", ext_data[0:2])[0]
            body = ext_data[2:2 + list_len]
            for i in range(0, len(body) - 1, 2):
                val = struct.unpack("!H", body[i:i + 2])[0]
                if not _is_grease(val):
                    curves.append(val)
        elif ext_type == 11 and len(ext_data) >= 1:         # ec_point_formats
            list_len = ext_data[0]
            point_formats.extend(ext_data[1:1 + list_len])
        offset += ext_len
    return ext_types, curves, point_formats


def parse_client_hello(tcp_payload: bytes):
    """Returns a dict of raw ClientHello fields, or None if this isn't one. Deliberately
    tolerant of short/malformed data — a passive tap sees plenty of non-TLS traffic on
    any given port and can't ask for a retransmit, so this fails closed, never raises."""
    try:
        if len(tcp_payload) < 6 or tcp_payload[0] != TLS_HANDSHAKE_CONTENT_TYPE:
            return None
        if tcp_payload[5] != CLIENT_HELLO:
            return None

        pos = 9  # record header(5) + handshake type(1) + handshake length(3)
        client_version = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
        pos += 2 + 32  # version + random

        session_id_len = tcp_payload[pos]
        pos += 1 + session_id_len

        cipher_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
        pos += 2
        cipher_bytes = tcp_payload[pos:pos + cipher_len]
        pos += cipher_len
        ciphers = [
            v for i in range(0, len(cipher_bytes) - 1, 2)
            if not _is_grease(v := struct.unpack("!H", cipher_bytes[i:i + 2])[0])
        ]

        compression_len = tcp_payload[pos]
        pos += 1 + compression_len

        extensions, curves, point_formats = [], [], []
        if pos + 2 <= len(tcp_payload):
            ext_total_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
            pos += 2
            extensions, curves, point_formats = _parse_extensions(
                tcp_payload, pos, pos + ext_total_len
            )

        return {
            "version": client_version, "ciphers": ciphers,
            "extensions": extensions, "curves": curves, "point_formats": point_formats,
        }
    except (struct.error, IndexError):
        return None


def parse_server_hello(tcp_payload: bytes):
    """Same idea for the server's reply — JA3S. ServerHello picks exactly ONE cipher
    (not a list) and carries no curves/point-formats fields at all."""
    try:
        if len(tcp_payload) < 6 or tcp_payload[0] != TLS_HANDSHAKE_CONTENT_TYPE:
            return None
        if tcp_payload[5] != SERVER_HELLO:
            return None

        pos = 9
        server_version = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
        pos += 2 + 32

        session_id_len = tcp_payload[pos]
        pos += 1 + session_id_len

        cipher = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
        pos += 2
        pos += 1  # single compression-method byte in ServerHello

        extensions = []
        if pos + 2 <= len(tcp_payload):
            ext_total_len = struct.unpack("!H", tcp_payload[pos:pos + 2])[0]
            pos += 2
            extensions, _, _ = _parse_extensions(tcp_payload, pos, pos + ext_total_len)

        return {"version": server_version, "cipher": cipher, "extensions": extensions}
    except (struct.error, IndexError):
        return None


def ja3_digest(hello: dict) -> str:
    """Standard JA3 string: TLSVersion,Ciphers,Extensions,Curves,PointFormats
    (dash-joined lists), MD5-hashed. Matches the original Salesforce JA3 spec so any
    hash you pull from a public blacklist feed will compare directly."""
    parts = [
        str(hello["version"]),
        "-".join(str(c) for c in hello["ciphers"]),
        "-".join(str(e) for e in hello["extensions"]),
        "-".join(str(c) for c in hello["curves"]),
        "-".join(str(p) for p in hello["point_formats"]),
    ]
    return hashlib.md5(",".join(parts).encode()).hexdigest()


def ja3s_digest(hello: dict) -> str:
    """JA3S string: TLSVersion,Cipher,Extensions."""
    parts = [str(hello["version"]), str(hello["cipher"]),
             "-".join(str(e) for e in hello["extensions"])]
    return hashlib.md5(",".join(parts).encode()).hexdigest()


class JA3Tracker:
    """Tracks JA3/JA3S sightings and flags: (1) exact blacklist matches, and (2) rare,
    never-before-seen fingerprints — a weak but real signal, since malware families
    often reuse a stable, uncommon TLS stack fingerprint, whereas normal browsers cluster
    into a small number of extremely common fingerprints. This is intentionally a
    coarse first pass, not a claim of high precision — say that plainly in the report,
    same tone as the RF's synthetic-data caveat."""

    def __init__(self, blacklist=None, window_seconds=300):
        self.blacklist = blacklist or set()
        self.window = window_seconds
        self.sightings = defaultdict(list)   # ja3_hash -> [(ts, src_ip), ...]
        self.seen_hashes = set()

    def record(self, ja3_hash: str, src_ip: str, ts: float) -> bool:
        """Returns True if this is the first time this fingerprint has ever been seen."""
        self.sightings[ja3_hash].append((ts, src_ip))
        cutoff = ts - self.window
        self.sightings[ja3_hash] = [s for s in self.sightings[ja3_hash] if s[0] >= cutoff]
        is_first = ja3_hash not in self.seen_hashes
        self.seen_hashes.add(ja3_hash)
        return is_first

    def is_blacklisted(self, ja3_hash: str) -> bool:
        return ja3_hash in self.blacklist

    def prevalence(self, ja3_hash: str) -> dict:
        recs = self.sightings.get(ja3_hash, [])
        return {"sightings_in_window": len(recs), "unique_sources": len({s for _, s in recs})}
