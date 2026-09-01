# SLUSH - Passive Threat Detection for Unidirectional Networks

SLUSH watches network traffic and tells you when something's wrong. That's it; it never touches a flow table, never sends a packet back, never mitigates anything. It just watches, scores, and alerts.

That constraint isn't a limitation we ended up with by accident. It's the whole point of the project.

## Why "passive-only" is the actual design

This started life as [PS26145](https://github.com/advait-r/DDOS-Mitigation-Mininet) for NTRO at SIH 2026 - *"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic."* Unidirectional means exactly what it sounds like: think a data diode, a SPAN/mirror port, a tap sitting on a link that physically cannot send anything back upstream. A lot of network security tooling quietly assumes it can react, drop the flow, reset the connection, push a blocklist. None of that is on the table here. If the sensor can't talk back to the wire, "detect and block" collapses into just "detect," and the entire system has to be built around that from the ground up rather than bolted on as an afterthought.

So the controller in this repo is read-only by construction: `packet_in_handler` learns MACs and installs *forwarding* rules so traffic keeps flowing, there is no code path anywhere that writes a drop rule. The only thing a detection produces is a line appended to `alerts.jsonl`. Everything downstream (the dashboard, the hardware indicator) is a consumer of that file, never a controller of the network.

The earlier [DDOS-Mitigation-Mininet](https://github.com/advait-r/DDOS-Mitigation-Mininet) project I built is the active-mitigation sibling to this — same Mininet/os_ken/Random-Forest bones, opposite philosophy. Worth a look if you want to see what changes when the sensor is allowed to fight back.

## What it actually catches

Not just DDoS. Once you're committed to "alert only," you might as well listen for everything that shows up as a flow, timing, or DNS-query anomaly:

| Threat class | What triggers it |
|---|---|
| `ddos` | Flow-count gate + Random Forest confirms a volumetric flood toward one destination |
| `ddos` (adaptive override) | Gate saturates *and* source-IP entropy is high — the flood is spoofed/distributed, so the RF verdict is overruled |
| `exfiltration` | Either the RF calls it on a gated flow, or a single flow crosses a large-byte threshold outright, independent of flow count |
| `recon_scan` | One source fanning out across many destination ports or hosts in a short window |
| `dga_dns` | A single DNS query with a short, high-entropy pseudo-random subdomain |
| `dns_tunnel` | *Repeated* long, high-entropy queries to the same base domain — the dnscat2/iodine signature |
| `c2_beacon` | Regular, low-jitter check-ins from one source to one dst:port — at least 6 connections, timing coefficient of variation ≤ 0.15, mean interval between 5s and 300s |
| `slowloris` | Many (≥ 20) concurrent long-lived (≥ 15s), near-empty (≤ 500 bytes) flows converging on one dst:port |

`encrypted_malware` (JA3/TLS-metadata fingerprinting) is reserved in the taxonomy but not wired up yet. Rather than silently omitting it, it shows up greyed out at zero on the dashboard's breakdown chart, labeled "not wired up yet," until a detector for it exists.

## Architecture

```
Mirrored/tapped traffic (unidirectional — no return path)
        │
   OpenFlow switch, table-miss → controller
        ▼
┌───────────────────────────────────────────────────────────────┐
│               PassiveThreatController (os_ken)                  │
│                                                                   │
│  packet_in_handler (runs on every IP packet, regardless of        │
│  whether the switch has already learned the destination MAC)      │
│    ├─ forwards normally (learns MAC → port, installs 5-tuple-      │
│    │   pinned idle/hard-timeout rules — traffic never stalls)      │
│    ├─ UDP/53 → DNS feature extraction (scapy)                      │
│    │     ├─ DGA check (single-query subdomain entropy)              │
│    │     └─ tunnel check (rate + entropy to the same base domain)   │
│    ├─ SYN-only / UDP-to-new-port → ScanTracker fan-out               │
│    └─ every fresh TCP SYN → BeaconTracker interval/jitter check       │
│                                                                   │
│  _monitor (every 5s) → polls OFPFlowStatsRequest AND writes a     │
│    heartbeat to activity.jsonl (drives the dashboard's LIVE/IDLE  │
│    indicator)                                                     │
│                                                                   │
│  flow_stats_reply_handler                                         │
│    Path 1 — per-destination flow-count gate                        │
│      rolling avg / 100 → anomaly_score                             │
│      score > 0.60 → classify matching flows with the RF             │
│      score ≥ 0.95 AND src-entropy high → override to ddos           │
│      backscatter check suppresses reversed SYN-flood RST fan-in       │
│      before it gets misattributed to the victim as the "attacker"     │
│    Path 2 — large-single-flow trigger                                │
│      byte_count ≥ 100,000 → classify regardless of the flow-count     │
│      gate (catches slow exfil the gate alone can't see)               │
│    Path 3 — slowloris fan-in                                          │
│      many concurrent long, near-empty flows against one dst:port       │
│                                                                   │
│  _raise_alert → dedupes with a 15s cooldown per                    │
│    (src, dst, threat_class) → appends to alerts.jsonl              │
└───────────────────────────────────────────────────────────────┘
        │
        ├──▶ dashboard/app.py — Flask + Chart.js, polls the log,
        │     shows live feed / threat mix / a growing session-long
        │     activity timeline (taxonomy fetched once from /api/meta
        │     so colors/labels/icons live in one place, not duplicated
        │     between Python and JS)
        │
        └──▶ controller/pico_bridge.py — tails alerts.jsonl, writes
              a 0.00–1.00 score over serial to a Pico, which drives
              a green/yellow/red LED (see below)
```

## Repo layout

```
Slush/
├── controller/
│   ├── controller.py      # PassiveThreatController — everything above lives here
│   ├── features.py        # shannon_entropy + ScanTracker (recon) + BeaconTracker (c2)
│   ├── dns_features.py     # qname feature extraction + TunnelTracker
│   ├── alerting.py          # Alert dataclass + AlertSink (append-only writer)
│   ├── pico_bridge.py        # serial bridge: alerts.jsonl → Pico LED/buzzer
│   ├── run_controller.py      # eventlet bootstrap + os_ken entrypoint
│   └── model_RF.pkl            # trained 3-class Random Forest
├── mininet/
│   └── topology.py               # 4-host single-switch topology, h3 = attacker, h4 = victim
├── ml/
│   ├── generate_dataset.py        # synthetic ddos/benign/exfiltration flow generator
│   ├── train_model.py              # trains + saves model_RF.pkl
│   └── *_old.py                     # first pass — binary classifier, kept for the diff
├── dashboard/
│   └── app.py                        # live dashboard, reads alerts.jsonl + activity.jsonl
├── alerts.jsonl                       # the entire "output" of the system, one JSON line per alert
└── activity.jsonl                      # single-line heartbeat, overwritten every poll — liveness only, not a log
```

## Running it

You'll need Mininet + Open vSwitch, same as any os_ken project.

**1. Install dependencies**

```bash
python3 -m venv venv
source venv/bin/activate
pip install "eventlet>=0.41" os-ken scapy pandas scikit-learn numpy joblib flask pyserial

sudo apt install -y mininet openvswitch-switch
sudo service openvswitch-switch start
```

**2. Train the model**

```bash
cd ml
python3 generate_dataset.py    # writes dataset.csv
python3 train_model.py          # writes ../controller/model_RF.pkl
```

**3. Start the controller**

```bash
cd controller
python3 run_controller.py
```

**4. Bring up the network and throw traffic at it**

```bash
sudo python3 mininet/topology.py
```

```
mininet> h3 hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.4 &
mininet> h3 nmap -p 1-1000 10.0.0.4
mininet> h1 dig @<dns-server> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tunnel.example.com
mininet> h3 for i in $(seq 1 8); do curl -s http://10.0.0.4:9001/ >/dev/null; sleep 20; done   # beacon sim — fixed-interval check-ins
mininet> h3 slowhttptest -c 1000 -H -i 10 -r 200 -u http://10.0.0.4/ -p 3                       # slowloris (needs slowhttptest installed)
```

Watch the controller terminal for `[POLL]` → `[SCORE]` → `[GATE TRIGGERED]` → `[ALERT]`, and confirm nothing ever shows up in the flow table beyond normal forwarding:

```bash
sudo ovs-ofctl dump-flows s1
```

**5. Watch it live**

```bash
cd dashboard
python3 app.py    # http://localhost:8080
```

The Attack Activity chart runs for the life of the dashboard process — it doesn't scroll old attacks off after a fixed window, so something that fired 20 minutes ago is still visible if you scrub back across the timeline.

## The physical alert light

This is the part that isn't in most SIH submissions, and honestly the part I enjoyed building most. `pico_bridge.py` tails `alerts.jsonl` and writes a plain `score\n` float over serial to a Raspberry Pi Pico:

- **< 0.60** → green, idle. A heartbeat keeps it refreshed every 2s so a *silent* Pico reads as "connection dropped," not "all clear."
- **0.60–0.94** → yellow, short beep.
- **≥ 0.95** → red, continuous alarm, held for 5 seconds past the last alert so a single momentary spike doesn't flicker on and off.

The idea was simple: a SOC dashboard is great until nobody's looking at the screen. A light on the desk that goes from green to red doesn't need anyone tabbed over to it.

```bash
python3 controller/pico_bridge.py /dev/ttyACM1
```

## Where the classifier came from

`ml/generate_dataset_old.py` and `train_model_old.py` are the first version - binary, attack-vs-benign, three features. They're still in the repo on purpose. The move to a 3-class model (`ddos` / `benign` / `exfiltration`) with a fourth feature, `bytes_per_packet`, came directly from a specific failure: a slow, sustained exfiltration flow looks *nothing* like the many-small-packets shape of a flood, and the old model had no way to represent that difference at all. `bytes_per_packet` turned out to be the single strongest separator between the two attack classes once it was added.

`recon_scan`, `dga_dns`, `dns_tunnel`, `c2_beacon`, and `slowloris` don't go through the RF at all — they're each a purpose-built rule/tracker over their own signature (fan-out, single-query entropy, repeated-query rate, inter-arrival jitter, and concurrent near-empty flows respectively), since none of those shapes fit the packet/byte/duration features the RF was trained on.

## Known gaps, stated plainly

- **The RF's features are per-flow.** Distributed floods with spoofed sources reveal themselves through *flow-table cardinality*, which the RF never sees directly, this is exactly why the adaptive-override path exists as a separate, non-ML check on source-IP entropy. The two signals corroborate each other; neither is sufficient alone.
- **`c2_beacon` detection depends on the flow-install match including source port.** The install match in `packet_in_handler` previously wildcarded `tcp_src`/`udp_src`. Once the first SYN of a beacon's connection installs a cached forwarding rule for `(src, dst, proto, dst_port)`, every *later* check-in from that same beacon matches the cached rule at the switch and never generates another `packet_in` — so `BeaconTracker` never accumulates the ≥6 events it needs, and the detector silently never fires no matter how long the beacon runs. Pinning `tcp_src`/`udp_src` in the match fixes it, at the cost of one flow-table entry per connection instead of per host pair — worth double-checking after any refactor of that block, since it's an easy regression to reintroduce.
- **`ATTACK_META['slowloris']['implemented']` in `dashboard/app.py` still reads `False`**, even though `controller.py`'s Path 3 actively raises `slowloris` alerts today. Until that flag is flipped, real slowloris alerts still land correctly in the feed, KPIs, and timeline — only the breakdown chart's bar renders greyed out as "not wired up yet," which is misleading now that it is. One-line fix once you confirm Path 3 is stable.
- **`LARGE_FLOW_BYTES = 100,000` is a guess, not a measurement.** It was set against the synthetic dataset's exfiltration distribution, not against real captured traffic. It needs recalibrating once this runs against something other than Mininet.
- **DNS parsing runs on every UDP/53 packet via scapy**, separately from the os_ken forwarding path, on purpose — but that also means it's a second, unguarded parser sitting in the hot path. A malformed DNS packet is caught by a broad `except Exception`, which is safe but not diagnostic.
- **No throughput benchmark yet.** The dashboard says so honestly (`"not yet run"`) rather than presenting a made-up flows/sec number — that's `bench/throughput_test.py` territory, not yet built.

## Team

**SLUSH** — Team ID SIH135, SIH 2026, Problem Statement 26145 (National Technical Research Organisation)

Advait Rane (lead)  Raghvendra Singh  Manan Shirodkar  Bhumika Chintakindi  Ananya Vandekar  Gautham Nair
