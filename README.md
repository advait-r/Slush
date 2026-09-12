# SLUSH: Passive Threat Detection for Unidirectional Networks

SLUSH watches network traffic and tells you when something looks wrong. It never touches the flow table to block anything, never sends a packet backward toward the source, and never tries to mitigate what it sees. It only watches, scores what it sees, and writes an alert. That is the whole job, and it is a deliberate one.

## Why this project exists

This was built for **PS26145** at SIH 2026, submitted by NTRO (the National Technical Research Organisation): *"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic."*

The problem statement describes something specific: a gateway or peering link where traffic is copied off with a mirror port or a hardware data diode. The monitoring side can see everything crossing that link, but there is no path back. Nothing it does can reach the production network, on purpose. That design choice removes an entire category of risk, where a compromised monitoring box becomes the attacker's way into the network it was supposed to be watching, and it keeps a clean record of what happened for anyone doing forensics afterward.

The catch is that anything you build to sit in that enclave has to work with only what it can passively observe: captured packets, exported flow records, and whatever metadata you can derive from them. No probing the source. No completing a handshake yourself. No command sent back down the wire, ever.

SLUSH is built around that constraint from the ground up rather than added on top of an active system afterward. `packet_in_handler` in the controller learns MAC addresses and installs forwarding rules so traffic keeps moving normally, but there is no code path anywhere in this repository that writes a drop rule, resets a connection, or blocks anything. The only thing a detection produces is one line appended to `alerts.jsonl`. Everything downstream of that, the dashboard, the physical alert light, only reads that file. Nothing reads it and acts back onto the network.

## How this maps to the problem statement

The problem statement asks for six threat categories and five architectural constraints. Here is where each one actually stands in this repository, stated plainly rather than glossed over.

**Threat categories (a through f):**

| # | Required detection | What SLUSH does about it |
|---|---|---|
| a | Volumetric/protocol DDoS from flow rate and source-IP entropy | A Random Forest classifies aggregated flow shape (packet count, byte count, duration, bytes per packet), backed by an entropy-based adaptive override for spoofed or distributed floods, plus a packet-level tracker that catches floods a switch never installs a flow rule for at all |
| b | Botnet C2 beaconing from periodicity and inter-arrival timing | A dedicated tracker measures the mean interval and jitter between connection attempts from one source to one destination and port |
| c | DGA domains and DNS tunnelling from entropy and query anomalies | DGA is caught from a single high-entropy query label. Tunnelling is caught from repeated, long, high-entropy queries to the same base domain over time |
| d | Malware inside encrypted sessions from TLS metadata | JA3/JA3S fingerprinting off the ClientHello and ServerHello, checked against a blacklist feed and flagged when a fingerprint looks rare. No payload is ever touched |
| e | Reconnaissance and port scanning from fan-out patterns | A tracker counts unique destination ports and hosts touched by one source in a short window |
| f | Data exfiltration from asymmetric flow volume | Caught two ways: through the same Random Forest gate as DDoS, and independently by a large single-flow trigger that fires regardless of flow count, since exfiltration is often one sustained flow rather than many |

**Architecture constraints (a through e):**

| # | Requirement | Status |
|---|---|---|
| a | Read-only ingest, no return path | Met. No flow-mod anywhere ever installs a block or a redirect. See `packet_in_handler` |
| b | No payload decryption | Met. TLS is read from the handshake only, which is sent in the clear by the protocol itself. DNS is read from the query name, which is also plaintext |
| c | Streaming, not batch | Met. Packet-triggered detectors (scan, DGA, tunnelling, beaconing) fire on the same event that produced them. Flow-based detectors (DDoS, exfiltration, slowloris) are bounded by a five-second poll interval, not an end-of-run report |
| d | Stated and demonstrated throughput | **Not yet done.** There is no throughput benchmark script in this repository yet. The dashboard says so honestly rather than showing a made-up number |
| e | Standardized alert schema | Met. Every alert is a JSON record with a timestamp, a flow identifier, a threat class, a confidence score, a severity, and supporting evidence, written by one shared `Alert` dataclass so every detector produces the same shape |

## What it actually catches

| Threat class | What triggers it |
|---|---|
| `ddos` | The flow-count gate fires and the Random Forest confirms a volumetric flood toward one destination |
| `ddos` (adaptive override) | The gate is saturated and source-IP entropy is high, meaning the flood is spoofed or distributed, so the RF verdict gets overruled by the entropy signal directly |
| `exfiltration` | Either the RF calls it on a gated flow, or a single flow crosses a large-byte threshold outright, independent of flow count |
| `recon_scan` | One source fans out across many destination ports or hosts in a short window |
| `dga_dns` | A single DNS query has a short, high-entropy subdomain that reads as machine-generated rather than a real word |
| `dns_tunnel` | Repeated long, high-entropy queries land against the same base domain over time, the signature dnscat2 or iodine leaves behind |
| `c2_beacon` | A source checks in at a regular interval to the same destination and port, at least six times, with very little jitter between check-ins |
| `slowloris` | Many long-lived, near-empty flows converge on the same destination and port at once |
| `encrypted_malware` | A TLS handshake fingerprint matches a known-bad JA3 hash, or looks rare enough to be worth flagging |

None of the rule-based detectors (`recon_scan`, `dga_dns`, `dns_tunnel`, `c2_beacon`, `slowloris`) go through the Random Forest. Each one has a shape that the RF's four features (packet count, byte count, duration, bytes per packet) simply cannot represent, so each gets its own purpose-built tracker instead of being forced through a model that was never trained on that pattern.

## Architecture

```
Mirrored or tapped traffic, one direction only, no return path
        |
   OpenFlow switch, table-miss goes to the controller
        v
+-------------------------------------------------------------------+
|              PassiveThreatController (os_ken)                      |
|                                                                     |
|  packet_in_handler runs on every IP packet, whether or not the     |
|  switch has already learned the destination MAC                   |
|    - forwards traffic normally, installs 5-tuple forwarding rules  |
|      so nothing stalls                                             |
|    - feeds a packet-volume tracker per destination, which sees     |
|      floods that never earn a switch flow entry at all             |
|    - UDP to port 53 goes through DNS feature extraction            |
|        - single-query entropy check for DGA                        |
|        - repeated-query rate and entropy check for tunnelling      |
|    - a SYN-only packet or a fresh UDP destination feeds the        |
|      scan tracker's fan-out count                                  |
|    - every fresh TCP handshake feeds the beacon tracker's          |
|      interval and jitter check                                     |
|    - a TLS ClientHello or ServerHello feeds the JA3 tracker         |
|                                                                     |
|  every five seconds: polls flow stats from the switch, checks the  |
|  packet-volume tracker directly, and writes a heartbeat so the     |
|  dashboard knows the enclave is alive                              |
|                                                                     |
|  on each flow-stats reply:                                         |
|    Path 1, per-destination flow-count gate                         |
|      rolling average of flow count feeds an anomaly score          |
|      once the score passes threshold, aggregate flows per source   |
|      and classify with the Random Forest                           |
|      a backscatter check keeps reflected traffic from being        |
|      misread as an attack running the wrong direction              |
|      a shape check keeps slow, near-empty flows from being fed     |
|      to a model that has no label for them                         |
|      high score plus high source entropy overrides straight to     |
|      a DDoS verdict, independent of what the RF says                |
|    Path 2, large single-flow trigger                                |
|      any flow over the byte threshold gets classified regardless   |
|      of flow count, which is how a slow exfiltration flow gets     |
|      caught even when it never trips the count gate                |
|    Path 3, slowloris                                                |
|      many concurrent long, near-empty flows converging on one       |
|      destination and port, checked directly rather than through    |
|      the model                                                     |
|                                                                     |
|  every alert is deduplicated with a cooldown window, then           |
|  appended to alerts.jsonl                                           |
+-------------------------------------------------------------------+
        |
        +--> dashboard/app.py, a Flask page with live charts that
        |    polls alerts.jsonl and activity.jsonl and shows the
        |    feed, the threat mix, and a timeline that runs for the
        |    life of the session
        |
        +--> controller/pico_bridge.py, which tails alerts.jsonl and
             writes a score over serial to a Raspberry Pi Pico, which
             drives a physical green, yellow, or red light
```

## Repository layout

```
Slush/
├── controller/
│   ├── controller.py       PassiveThreatController, everything above lives here
│   ├── features.py         shannon_entropy, ScanTracker, BeaconTracker, VolumeTracker
│   ├── dns_features.py     DNS query feature extraction and TunnelTracker
│   ├── tls_features.py     JA3/JA3S parsing and JA3Tracker
│   ├── alerting.py         the Alert record and the append-only writer
│   ├── ja3_blacklist.txt   known-bad TLS fingerprints, sourced from abuse.ch
│   ├── pico_bridge.py      serial bridge from alerts.jsonl to the Pico light
│   ├── run_controller.py   eventlet bootstrap and os_ken entry point
│   └── model_RF.pkl        the trained Random Forest
├── mininet/
│   └── topology.py         four-host, single-switch topology, h3 is the attacker, h4 is the victim
├── ml/
│   ├── generate_dataset.py  builds the synthetic training set
│   ├── train_model.py        trains and saves model_RF.pkl
│   └── *_old.py               the original binary classifier, kept for comparison
├── dashboard/
│   └── app.py                the live dashboard
├── alerts.jsonl                one JSON line per alert, the entire output of the system
└── activity.jsonl               a single overwritten line, a heartbeat, not a log
```

## Running it

You will need Mininet and Open vSwitch, same as any os_ken project.

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

The generator produces about 20,000 synthetic flows: 70 percent benign, 20 percent DDoS, 10 percent exfiltration, following the Poisson and exponential flow shapes described in the problem statement's suggested data sources.

**3. Start the controller**

```bash
cd controller
python3 run_controller.py
```

**4. Bring up the network and send it some traffic**

```bash
sudo python3 mininet/topology.py
```

```
mininet> h3 hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.4
mininet> h3 nmap -p 1-1000 10.0.0.4
mininet> h3 bash -c 'while true; do sub=$(openssl rand -hex 20); dig +time=1 +tries=1 TXT @10.0.0.4 "${sub}.tunnel.domain.com"; sleep 0.1; done'
mininet> h3 for i in $(seq 1 8); do curl -s http://10.0.0.4:9001/ >/dev/null; sleep 20; done
mininet> h3 slowhttptest -c 200 -H -g -o slowloris_test -i 10 -r 200 -t GET -u http://10.0.0.4:8080/ -l 60
```

Watch the controller terminal for `[POLL]`, then `[SCORE]`, then `[GATE TRIGGERED]`, then `[ALERT]`, and confirm nothing ever shows up in the flow table beyond normal forwarding:

```bash
sudo ovs-ofctl dump-flows s1
```

**5. Watch it live**

```bash
cd dashboard
python3 app.py    # http://localhost:8080
```

The activity chart runs for the whole life of the dashboard process. It does not scroll old attacks off the screen after a fixed window, so something that fired twenty minutes ago is still there if you scrub back across the timeline.

## The physical alert light

This part is not something most SIH teams build, and it was the part I enjoyed most. `pico_bridge.py` tails `alerts.jsonl` and writes a plain score, as a number between 0 and 1, over serial to a Raspberry Pi Pico.

- Below 0.60: green, idle. A heartbeat refreshes it every two seconds so a Pico that has stopped responding reads as a dropped connection, not as "all clear."
- 0.60 to 0.94: yellow, a short beep.
- 0.95 and above: red, a continuous alarm, held for five seconds past the last alert so one momentary spike does not flicker on and off.

The reasoning is simple. A dashboard is only useful if someone is looking at it. A light on the desk that turns from green to red does not need anyone tabbed over to a browser window.

```bash
python3 controller/pico_bridge.py /dev/ttyACM1
```

## Where the classifier came from

`ml/generate_dataset_old.py` and `train_model_old.py` are the first version of this: a binary attack-versus-benign classifier with three features. They are still in the repository on purpose, kept for the diff.

The move to a three-class model, DDoS versus benign versus exfiltration, with a fourth feature added, bytes per packet, came from a specific failure in that first version. A slow, sustained exfiltration flow does not look anything like the many-small-packets shape of a flood, and the old model had no way to represent that difference at all. Bytes per packet turned out to be the strongest single separator between the two attack classes once it was added.

Recon scanning, DGA detection, DNS tunnelling, beaconing, and slowloris never go anywhere near the Random Forest. Each one is a fan-out count, a single-query entropy check, a repeated-query rate, an inter-arrival jitter measurement, or a concurrent-flow count, and none of those shapes fit the packet, byte, and duration features the RF was actually trained on.

## Known gaps, stated plainly

- **DNS tunnelling entropy is measured on the wrong label for multi-label domains.** The current feature extraction reuses the same "second-to-last label" entropy value for both DGA and tunnelling checks. That is correct for DGA, where the random part sits directly in that position, but wrong for tunnelling, where a real payload like `<encoded-data>.tunnel.example.com` puts the random data further out and leaves the second-to-last label as an ordinary word. This needs a separate entropy calculation over everything before the registrable domain, not the same field reused for two different jobs.
- **Alert cooldown coalescing for spoofed floods is half-wired.** The code computes a `cooldown_src` value meant to collapse hundreds of one-off alerts from a randomized-source flood into one, but the actual cooldown key still keys off the real (fake) source IP, so the coalescing never takes effect yet. One-line fix, not yet applied.
- **The packet-volume tracker's dictionary never gets cleaned up.** Once a destination stops seeing traffic, its entry stays in memory with an empty list forever. Harmless for a short demo run, worth adding a pruning pass before running this for hours at a time.
- **`LARGE_FLOW_BYTES` is a guess, not a measurement.** It was set against the synthetic dataset's exfiltration distribution, not against anything captured live. It needs recalibrating once this runs against traffic that is not from Mininet.
- **The JA3 blacklist is a snapshot from abuse.ch, not a live feed.** It is a real, historically confirmed list, but it will miss anything newer than when it was pulled. The refresh command is in the file's own header comment.
- **No throughput benchmark exists yet.** The dashboard says so honestly rather than presenting a number that was never measured. This is the one architectural requirement from the problem statement not yet met.
- **DNS parsing runs through scapy on every UDP/53 packet, separately from the main os_ken forwarding path.** A malformed DNS packet is caught by a broad exception handler, which is safe but does not tell you anything about what went wrong if it ever does.

## Team

**SLUSH**, Team ID SIH135, SIH 2026, Problem Statement 26145, National Technical Research Organisation

Advait Rane (lead), Raghvendra Singh, Manan Shirodkar, Bhumika Chintakindi, Ananya Vandekar, Gautham Nair
