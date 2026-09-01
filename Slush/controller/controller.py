from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
import joblib
import json
import os
import time
import pandas as pd

from scapy.layers.l2 import Ether as ScapyEther
from scapy.layers.dns import DNS
from dns_features import dns_query_features, TunnelTracker

from alerting import Alert, AlertSink
from features import shannon_entropy, ScanTracker
from features import shannon_entropy, ScanTracker, BeaconTracker

class PassiveThreatController(app_manager.OSKenApp):
    """Read-only enclave controller. No OFPFlowMod ever installs a drop rule here —
    the only output of a confirmed threat is an Alert written to alerts.jsonl."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    ANOMALY_THRESHOLD = 0.6
    POLL_INTERVAL = 5  # seconds
    SCAN_PORT_THRESHOLD = 15     # unique dst ports from one src within window -> recon alert
    SCAN_HOST_THRESHOLD = 10     # unique dst hosts from one src within window -> recon alert
    ENTROPY_MIN_FOR_OVERRIDE = 3.0

    DGA_ENTROPY_THRESHOLD = 3.3      # single-query high-entropy pseudo-random label
    DGA_MAX_SLD_LEN = 30
    TUNNEL_QUERY_RATE_THRESHOLD = 2.0   # queries/sec to the SAME base domain
    TUNNEL_MIN_AVG_LEN = 40
    TUNNEL_MIN_AVG_ENTROPY = 3.0
     




    SLOWLORIS_MIN_DURATION = 15         # flow must have been open at least this long
    SLOWLORIS_MAX_BYTES = 500             # ...while having sent almost nothing
    SLOWLORIS_MIN_CONCURRENT = 20          # this many such flows to one dst:port at once

    BEACON_WINDOW_SECONDS = 600      # look back 10 minutes' worth of connection attempts
    BEACON_MIN_EVENTS = 6             # need at least this many check-ins before trusting the interval math
    BEACON_JITTER_CV_MAX = 0.15        # near-perfectly-regular timing — real humans are jitterier than this
    BEACON_INTERVAL_MIN = 5              # seconds — below this it's probably just a busy legit connection
    BEACON_INTERVAL_MAX = 300
    # NEW: a single flow this large bypasses the flow-count gate entirely. Exfiltration is
    # often ONE big flow, not many small ones — if we only escalated flows when flow_count
    # to a destination spikes, an exfil flow could sail through Stage 1 forever.
    # Tune this against your real Mininet flow byte_counts once you've run a live test —
    # this starting value is a guess based on the synthetic dataset, not measured traffic.
    LARGE_FLOW_BYTES = 100_000
    ALERT_COOLDOWN_SECONDS = 15 

    # BUG FIX: a SYN flood against a closed/unlistened port makes the victim's own kernel
    # fire back a TCP RST for every SYN. Because flood tools randomize the SOURCE port on
    # each packet, every RST comes back with a different DESTINATION port — which means
    # each one lands in its own flow-table entry at the switch. That produces a "many
    # distinct flows converging on one IP" pattern (PATH 1's trigger condition) pointed
    # STRAIGHT BACK at the real attacker, and PATH 1 has no way to tell that apart from a
    # genuine fan-in attack — it ends up alerting src=victim, dst=attacker. If the
    # candidate "attacker" (src_ip) is itself absorbing dramatically more traffic THIS
    # SAME POLL than the candidate "victim" (dst_ip), that asymmetry is the signature of
    # backscatter, not a real attack — the actual flood is already caught by PATH 1/2 in
    # the correct direction, so it's safe to suppress the reversed one.
    BACKSCATTER_VOLUME_RATIO = 5

    LABEL_MAP = {0: "ddos", 1: "benign", 2: "exfiltration"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        model_path = os.path.join(os.path.dirname(__file__), "model_RF.pkl")
        self.model = joblib.load(model_path)
        self.dst_history = {}        # dst_ip -> [flow_count per poll]        (unchanged from original)
        self.src_ip_history = {}     # dst_ip -> [[src_ips this poll], ...]   (for entropy)
        self.scan_tracker = ScanTracker(window_seconds=10)
        self.alert_cooldown = {}
        self.alert_sink = AlertSink(path=os.path.join(os.path.dirname(__file__), "..", "alerts.jsonl"))
        # BUG FIX: the dashboard's LIVE/IDLE indicator reads this path, but nothing in the
        # codebase was ever writing to it — the enclave could be running fine and it would
        # still show IDLE forever. _monitor() below already ticks on a fixed interval
        # regardless of traffic, so it's the right place to emit a heartbeat.
        self.activity_path = os.path.join(os.path.dirname(__file__), "..", "activity.jsonl")
        self.monitor_thread = hub.spawn(self._monitor)
        self.tunnel_tracker = TunnelTracker(window_seconds=30)
        self.beacon_tracker = BeaconTracker(window_seconds=self.BEACON_WINDOW_SECONDS,
                                     min_events=self.BEACON_MIN_EVENTS)

    def _ping_activity(self):
        """Overwrite (not append) a single-line heartbeat — this is a liveness signal,
        not a log, so it should never grow unbounded the way alerts.jsonl currently does."""
        try:
            with open(self.activity_path, "w") as f:
                f.write(json.dumps({"timestamp": time.time()}) + "\n")
        except OSError:
            pass

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif dp.id in self.datapaths:
            del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                 match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # BUG FIX: passive detection used to live inside `if out_port != OFPP_FLOOD`,
        # meaning it only ran once the switch had already learned the destination MAC.
        # A port scan's whole signature is touching hosts the switch has NEVER seen
        # traffic from before — those probes get OFPP_FLOOD'ed and were silently
        # skipping scan_tracker.record() entirely, so recon_scan could never accumulate
        # fanout. Same problem for a DNS resolver the controller hasn't learned yet.
        # Detection now runs on every IP packet regardless of the forwarding decision;
        # only flow-rule installation below stays gated on knowing the real out_port.
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt:
            # DNS-based detection (DGA + tunnelling) — query names are plaintext by
            # protocol, so this needs no payload decryption to satisfy that constraint.
            if udp_pkt and udp_pkt.dst_port == 53:
                qname = self._extract_dns_qname(msg.data)
                if qname:
                    feats = dns_query_features(qname)
                    # BUG FIX: previously passed the raw `qname` in as base_domain (so every
                    # randomized tunnel subdomain landed in its own bucket of size 1, and
                    # record() never returned it anyway — tunnel_score() was always scoring
                    # an empty (src, None) bucket). Now uses the real base domain and the
                    # fixed record() return value.
                    base_domain = self.tunnel_tracker.record(
                        ip_pkt.src, feats["base_domain"], time.time(),
                        feats["qname_len"], feats["sld_entropy"]
                    )

                    # DGA: ONE high-entropy pseudo-random label, normal domain length —
                    # this is what separates it from tunnelling below, which is
                    # REPEATED long queries against the same base domain.
                    if (feats["sld_entropy"] >= self.DGA_ENTROPY_THRESHOLD
                            and feats["qname_len"] <= self.DGA_MAX_SLD_LEN):
                        self._raise_alert(
                            threat_class="dga_dns",
                            src_ip=ip_pkt.src,
                            dst_ip=ip_pkt.dst,
                            confidence=min(1.0, feats["sld_entropy"] / 5.0),
                            evidence=feats,
                            proto=17, src_port=udp_pkt.src_port, dst_port=udp_pkt.dst_port,
                        )

                    tscore = self.tunnel_tracker.tunnel_score(ip_pkt.src, base_domain)
                    if (tscore["query_rate"] >= self.TUNNEL_QUERY_RATE_THRESHOLD
                            and tscore["avg_len"] >= self.TUNNEL_MIN_AVG_LEN
                            and tscore["avg_entropy"] >= self.TUNNEL_MIN_AVG_ENTROPY):
                        self._raise_alert(
                            threat_class="dns_tunnel",
                            src_ip=ip_pkt.src,
                            dst_ip=ip_pkt.dst,
                            confidence=min(1.0, tscore["query_rate"] / (self.TUNNEL_QUERY_RATE_THRESHOLD * 2)),
                            evidence=tscore,
                            proto=17, src_port=udp_pkt.src_port, dst_port=udp_pkt.dst_port,
                        )

            # Recon/port-scan detection
            dst_port = None
            src_port = None
            is_scan_probe = False
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
                src_port = tcp_pkt.src_port
                is_scan_probe = bool(tcp_pkt.bits & tcp.TCP_SYN) and not bool(tcp_pkt.bits & tcp.TCP_ACK)
            
                # NEW — feed every fresh TCP connection into the beacon tracker regardless
                # of whether it also looks like a scan probe; a beacon isn't a fan-out.
                if bool(tcp_pkt.bits & tcp.TCP_SYN) and not bool(tcp_pkt.bits & tcp.TCP_ACK):
                    self.beacon_tracker.record(ip_pkt.src, ip_pkt.dst, dst_port, time.time(), len(msg.data))
                    bscore = self.beacon_tracker.beacon_score(ip_pkt.src, ip_pkt.dst, dst_port)
                    if (bscore
                           and bscore["jitter_cv"] <= self.BEACON_JITTER_CV_MAX
                           and self.BEACON_INTERVAL_MIN <= bscore["mean_interval"] <= self.BEACON_INTERVAL_MAX):
                        self._raise_alert(
                            threat_class="c2_beacon",
                            src_ip=ip_pkt.src,
                            dst_ip=ip_pkt.dst,
                            confidence=min(1.0, 1 - bscore["jitter_cv"]),
                            evidence=bscore,
                       )

            elif udp_pkt:
                dst_port = udp_pkt.dst_port
                src_port = udp_pkt.src_port
                is_scan_probe = True

            if dst_port is not None and is_scan_probe:
                self.scan_tracker.record(ip_pkt.src, ip_pkt.dst, dst_port, time.time())
                fanout = self.scan_tracker.fanout(ip_pkt.src)
                if (fanout["unique_dst_ports"] >= self.SCAN_PORT_THRESHOLD
                        or fanout["unique_dst_hosts"] >= self.SCAN_HOST_THRESHOLD):
                    self._raise_alert(
                        threat_class="recon_scan",
                        src_ip=ip_pkt.src,
                        dst_ip=ip_pkt.dst,
                        confidence=min(1.0, fanout["unique_dst_ports"] / (self.SCAN_PORT_THRESHOLD * 2)),
                        evidence=fanout,
                        proto=6 if tcp_pkt else 17, src_port=src_port, dst_port=dst_port,
                    )

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt:
                match_kwargs = dict(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=ip_pkt.proto,   # ALWAYS pin protocol, even for ICMP (proto=1).
                    # Without this, an ICMP-triggered rule (ping) has no protocol restriction
                    # at all and silently becomes a wildcard that later TCP/UDP traffic
                    # between the same two hosts matches too — exactly what happened when
                    # `pingall` ran before the nmap scan: the ping's flow rule swallowed
                    # every scan probe at the switch, so the controller never saw them.
                )
                if tcp_pkt:
                    match_kwargs.update(tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
                elif udp_pkt:
                    match_kwargs.update(udp_src=udp_pkt.src_port, udp_dst=udp_pkt.dst_port)

                match = parser.OFPMatch(**match_kwargs)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,
                                         eth_type=eth.ethertype)

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                     match=match, instructions=inst,
                                     idle_timeout=30, hard_timeout=60)
            datapath.send_msg(mod)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        while True:
            self._ping_activity()
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.POLL_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    def _extract_dns_qname(self, raw_data):
        """Parse the raw Ethernet frame with scapy just for DNS — os_ken's packet lib
        doesn't need to know about it, this stays fully separate from the forwarding path."""
        try:
            scapy_pkt = ScapyEther(raw_data)
            if scapy_pkt.haslayer(DNS) and scapy_pkt[DNS].qd is not None:
                return scapy_pkt[DNS].qd.qname.decode(errors="ignore")
        except Exception:
            pass
        return None

    def _classify(self, packet_count, byte_count, duration):
        """Shared 4-feature classification path used by both the flow-count gate and the
        large-flow trigger below, so the two paths can never drift out of sync."""
        bytes_per_packet = byte_count / max(packet_count, 1)
        features = pd.DataFrame(
            [[packet_count, byte_count, duration, bytes_per_packet]],
            columns=["packet_count", "byte_count", "flow_duration", "bytes_per_packet"],
        )
        prediction = self.model.predict(features)[0]
        return self.LABEL_MAP.get(prediction, "unknown"), bytes_per_packet
    def _looks_like_backscatter(self, src_ip, dst_ip, dst_packet_totals):
        """True if src_ip (the candidate attacker for this fan-in) is itself absorbing
        far more traffic THIS POLL than dst_ip is — i.e. src_ip looks like the real
        traffic sink, not an attacker. See BACKSCATTER_VOLUME_RATIO above for why."""
        src_volume = dst_packet_totals.get(src_ip, 0)
        dst_volume = dst_packet_totals.get(dst_ip, 0)
        return src_volume > 0 and src_volume >= dst_volume * self.BACKSCATTER_VOLUME_RATIO

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dst_packet_totals = {}
        dst_flow_counts = {}
        dst_src_ips = {}   # dst_ip -> [src_ip, ...] seen this poll, feeds entropy
        flow_entries_this_poll = []

        for stat in ev.msg.body:
            match = stat.match
            src_ip = match.get('ipv4_src')
            dst_ip = match.get('ipv4_dst')
            if not src_ip or not dst_ip:
                continue

            packet_count = stat.packet_count
            byte_count = stat.byte_count
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            # 5-tuple support: these flow rules were installed with ip_proto and a dst
            # port pinned (see match_kwargs in packet_in_handler), so both are available
            # here. There's no src port in the match (never matched on it), so flow_id
            # for these aggregate, flow-stats-derived alerts is a 4-tuple + wildcard src port.
            flow_proto = match.get('ip_proto')
            flow_dst_port = match.get('tcp_dst', match.get('udp_dst'))

            dst_packet_totals[dst_ip] = dst_packet_totals.get(dst_ip, 0) + packet_count
            dst_flow_counts[dst_ip] = dst_flow_counts.get(dst_ip, 0) + 1
            dst_src_ips.setdefault(dst_ip, []).append(src_ip)
            flow_entries_this_poll.append(
                (src_ip, dst_ip, packet_count, byte_count, duration, flow_proto, flow_dst_port)
            )

        self.logger.info(
            "[POLL] saw %d flow entries this reply, dst_totals=%s, dst_flow_counts=%s",
            len(flow_entries_this_poll), dst_packet_totals, dst_flow_counts
        )

        # PATH 1 — volumetric gate: many flows converging on one destination (unchanged shape
        # from your original code, now routed through _classify + _raise_alert).
        for dst_ip, flow_count in dst_flow_counts.items():
            anomaly_score = self._compute_anomaly_score(dst_ip, flow_count)
            entropy = self._update_entropy(dst_ip, dst_src_ips.get(dst_ip, []))
            self.logger.info(
                "[SCORE] dst=%s flow_count=%d score=%.3f entropy=%.3f threshold=%.2f",
                dst_ip, flow_count, anomaly_score, entropy, self.ANOMALY_THRESHOLD
            )
            if anomaly_score <= self.ANOMALY_THRESHOLD:
                continue

            matching_flows = [e for e in flow_entries_this_poll if e[1] == dst_ip]
            self.logger.info(
                "[GATE TRIGGERED] dst=%s flow_count=%s score=%.2f entropy=%.2f — classifying %d flows",
                dst_ip, flow_count, anomaly_score, entropy, len(matching_flows)
            )

            for src_ip, flow_dst, packet_count, byte_count, duration, flow_proto, flow_dst_port in matching_flows:
                if self._looks_like_backscatter(src_ip, dst_ip, dst_packet_totals):
                    self.logger.info(
                        "[SUPPRESSED-BACKSCATTER] src=%s dst=%s — src is absorbing %dx+ more "
                        "traffic this poll than dst, this fan-in is almost certainly reply "
                        "backscatter from a flood running the other way",
                        src_ip, dst_ip, self.BACKSCATTER_VOLUME_RATIO
                    )
                    continue

                verdict, bytes_per_packet = self._classify(packet_count, byte_count, duration)

                # ADAPTIVE-OVERRIDE exists to catch spoofed/distributed floods — HIGH
                # source-IP entropy. A port scan from one source also inflates flow_count
                # (one flow per port probed) but has LOW entropy since it's nearly all one
                # source. Without gating on entropy here, a scan gets mislabeled "ddos".
                is_override = anomaly_score >= 0.95 and entropy >= self.ENTROPY_MIN_FOR_OVERRIDE
                if verdict in ("ddos", "exfiltration") or is_override:
                    threat_class = verdict if verdict != "benign" else "ddos"
                    reason = "RF" if verdict in ("ddos", "exfiltration") else "ADAPTIVE-OVERRIDE"
                    self._raise_alert(
                        threat_class=threat_class,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        confidence=anomaly_score if reason == "ADAPTIVE-OVERRIDE" else 0.85,
                        evidence={
                            "reason": reason,
                            "flow_count": flow_count,
                            "anomaly_score": round(anomaly_score, 3),
                            "src_entropy": round(entropy, 3),
                            "packet_count": packet_count,
                            "byte_count": byte_count,
                            "duration": round(duration, 2),
                            "bytes_per_packet": round(bytes_per_packet, 1),
                        },
                        proto=flow_proto, dst_port=flow_dst_port,
                    )

        # PATH 2 — large single-flow trigger: independent of flow_count, catches BOTH a
        # sustained single-source flood (huge packet_count/byte_count, one flow) and
        # exfiltration (huge byte_count, few packets) — anything the flow-count gate above
        # can't see because it only escalates when many DISTINCT flows hit one destination.
        for src_ip, dst_ip, packet_count, byte_count, duration, flow_proto, flow_dst_port in flow_entries_this_poll:
            if byte_count < self.LARGE_FLOW_BYTES:
                continue
            verdict, bytes_per_packet = self._classify(packet_count, byte_count, duration)
            if verdict == "benign":
                continue
            self._raise_alert(
                threat_class=verdict,
                src_ip=src_ip,
                dst_ip=dst_ip,
                confidence=0.8,
                evidence={
                    "reason": "LARGE_FLOW_TRIGGER",
                    "packet_count": packet_count,
                    "byte_count": byte_count,
                    "duration": round(duration, 2),
                    "bytes_per_packet": round(bytes_per_packet, 1),
                },
                proto=flow_proto, dst_port=flow_dst_port,
            )
        # PATH 3 — slowloris: many long-lived, near-empty flows converging on one dst:port.
        # Opposite signature from Path 1/2, so it needs its own gate rather than reusing the RF,
        # which was never trained on "duration high, bytes tiny."
        slow_flows_by_dst_port = {}
        for stat in ev.msg.body:
            match = stat.match
            src_ip = match.get('ipv4_src')
            dst_ip = match.get('ipv4_dst')
            dst_port = match.get('tcp_dst')
            if not src_ip or not dst_ip or dst_port is None:
                continue
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            if duration >= self.SLOWLORIS_MIN_DURATION and stat.byte_count <= self.SLOWLORIS_MAX_BYTES:
                slow_flows_by_dst_port.setdefault((dst_ip, dst_port), []).append(src_ip)

        for (dst_ip, dst_port), sources in slow_flows_by_dst_port.items():
            if len(sources) < self.SLOWLORIS_MIN_CONCURRENT:
                continue
            self._raise_alert(
                threat_class="slowloris",
                src_ip=sources[0] if len(set(sources)) == 1 else "multiple",
                dst_ip=dst_ip,
                confidence=min(1.0, len(sources) / (self.SLOWLORIS_MIN_CONCURRENT * 2)),
                evidence={
                    "dst_port": dst_port,
                    "concurrent_slow_flows": len(sources),
                    "unique_sources": len(set(sources)),
                },
            ) 
         


    def _compute_anomaly_score(self, dst_ip, flow_count):
        history = self.dst_history.setdefault(dst_ip, [])
        history.append(flow_count)
        if len(history) > 10:
            history.pop(0)
        avg = sum(history) / len(history)
        return min(avg / 100.0, 1.0)

    def _update_entropy(self, dst_ip, src_ips_this_poll):
        history = self.src_ip_history.setdefault(dst_ip, [])
        history.append(src_ips_this_poll)
        if len(history) > 10:
            history.pop(0)
        flat = [ip for poll in history for ip in poll]
        return shannon_entropy(flat)

    _PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}

    @classmethod
    def _build_flow_id(cls, proto, src_ip, src_port, dst_ip, dst_port):
        """5-tuple flow_id. src_port and/or proto are None for flow-stats-derived
        alerts (recon_scan/dns_tunnel/dga_dns from packet_in carry the full 5-tuple;
        ddos/exfiltration from flow stats never had src_port matched, so it renders
        as '*' — an honest wildcard rather than a guess)."""
        proto_name = cls._PROTO_NAMES.get(proto, str(proto) if proto is not None else "ip")
        sp = str(src_port) if src_port is not None else "*"
        dp = str(dst_port) if dst_port is not None else "*"
        return f"{proto_name}/{src_ip}:{sp}->{dst_ip}:{dp}"

    def _raise_alert(self, threat_class, src_ip, dst_ip, confidence, evidence,
                      proto=None, src_port=None, dst_port=None):
        key = (src_ip, dst_ip, threat_class)
        now = time.time()
        last_alert = self.alert_cooldown.get(key, 0)
        if now - last_alert < self.ALERT_COOLDOWN_SECONDS:
            return
        self.alert_cooldown[key] = now
        
        severity = "critical" if confidence > 0.9 else "high" if confidence > 0.75 else "medium"
        alert = Alert(
            timestamp=time.time(),
            flow_id=self._build_flow_id(proto, src_ip, src_port, dst_ip, dst_port),
            src_ip=src_ip,
            dst_ip=dst_ip,
            threat_class=threat_class,
            confidence=round(confidence, 3),
            severity=severity,
            evidence=evidence,
        )
        self.alert_sink.emit(alert)
        self.logger.info("[ALERT] %s src=%s dst=%s confidence=%.2f severity=%s",
                          threat_class, src_ip, dst_ip, confidence, severity)
