from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
import joblib
import os
import time
import pandas as pd

from scapy.layers.l2 import Ether as ScapyEther
from scapy.layers.dns import DNS
from dns_features import dns_query_features, TunnelTracker

from alerting import Alert, AlertSink
from features import shannon_entropy, ScanTracker


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

    # NEW: a single flow this large bypasses the flow-count gate entirely. Exfiltration is
    # often ONE big flow, not many small ones — if we only escalated flows when flow_count
    # to a destination spikes, an exfil flow could sail through Stage 1 forever.
    # Tune this against your real Mininet flow byte_counts once you've run a live test —
    # this starting value is a guess based on the synthetic dataset, not measured traffic.
    LARGE_FLOW_BYTES = 100_000
    ALERT_COOLDOWN_SECONDS = 15 

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
        self.monitor_thread = hub.spawn(self._monitor)
        self.tunnel_tracker = TunnelTracker(window_seconds=30)

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

        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)

            if eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)
                
                # DNS-based detection (DGA + tunnelling) — query names are plaintext by
                # protocol, so this needs no payload decryption to satisfy that constraint.
                if udp_pkt and udp_pkt.dst_port == 53:
                    qname = self._extract_dns_qname(msg.data)
                    if qname:
                        feats = dns_query_features(qname)
                        base_domain = self.tunnel_tracker.record(
                            ip_pkt.src, qname, time.time(), feats["qname_len"], feats["sld_entropy"]
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
                            )

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
                    match_kwargs.update(tcp_dst=tcp_pkt.dst_port)
                elif udp_pkt:
                    match_kwargs.update(udp_dst=udp_pkt.dst_port)

                match = parser.OFPMatch(**match_kwargs)

                # Recon/port-scan detection
                dst_port = None
                is_scan_probe = False
                if tcp_pkt:
                    dst_port = tcp_pkt.dst_port
                    is_scan_probe = bool(tcp_pkt.bits & tcp.TCP_SYN) and not bool(tcp_pkt.bits & tcp.TCP_ACK)
                elif udp_pkt:
                    dst_port = udp_pkt.dst_port
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
                        )
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

            dst_packet_totals[dst_ip] = dst_packet_totals.get(dst_ip, 0) + packet_count
            dst_flow_counts[dst_ip] = dst_flow_counts.get(dst_ip, 0) + 1
            dst_src_ips.setdefault(dst_ip, []).append(src_ip)
            flow_entries_this_poll.append((src_ip, dst_ip, packet_count, byte_count, duration))

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

            for src_ip, flow_dst, packet_count, byte_count, duration in matching_flows:
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
                    )

        # PATH 2 — large single-flow trigger: independent of flow_count, catches BOTH a
        # sustained single-source flood (huge packet_count/byte_count, one flow) and
        # exfiltration (huge byte_count, few packets) — anything the flow-count gate above
        # can't see because it only escalates when many DISTINCT flows hit one destination.
        for src_ip, dst_ip, packet_count, byte_count, duration in flow_entries_this_poll:
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

    def _raise_alert(self, threat_class, src_ip, dst_ip, confidence, evidence):
        key = (src_ip, dst_ip, threat_class)
        now = time.time()
        last_alert = self.alert_cooldown.get(key, 0)
        if now - last_alert < self.ALERT_COOLDOWN_SECONDS:
            return
        self.alert_cooldown[key] = now
        
        severity = "critical" if confidence > 0.9 else "high" if confidence > 0.75 else "medium"
        alert = Alert(
            timestamp=time.time(),
            flow_id=f"{src_ip}->{dst_ip}",
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
