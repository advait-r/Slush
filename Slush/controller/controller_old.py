from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4
import joblib
import os


class HybridDDoSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    ANOMALY_THRESHOLD = 0.6
    POLL_INTERVAL = 5  # seconds
    PROTECTED_IPS = {"10.0.0.4"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        model_path = os.path.join(os.path.dirname(__file__), "model_RF.pkl")
        self.model = joblib.load(model_path)
        self.dst_history = {}
        self.monitor_thread = hub.spawn(self._monitor)

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
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
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

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dst_packet_totals = {}
        dst_flow_counts = {}
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
            flow_entries_this_poll.append((src_ip, dst_ip, packet_count, byte_count, duration))

        self.logger.info(
            "[POLL] saw %d flow entries this reply, dst_totals=%s, dst_flow_counts=%s",
            len(flow_entries_this_poll), dst_packet_totals, dst_flow_counts
        )

        for dst_ip, flow_count in dst_flow_counts.items():
            anomaly_score = self._compute_anomaly_score(dst_ip, flow_count)
            self.logger.info(
                "[SCORE] dst=%s flow_count=%d score=%.3f threshold=%.2f",
                dst_ip, flow_count, anomaly_score, self.ANOMALY_THRESHOLD
            )
            if anomaly_score <= self.ANOMALY_THRESHOLD:
                continue

            for src_ip, flow_dst, packet_count, byte_count, duration in flow_entries_this_poll:
                if flow_dst != dst_ip:
                    continue
                features = [[packet_count, byte_count, duration]]
                prediction = self.model.predict(features)[0]

                self.logger.info(
                    "[GATE TRIGGERED] dst=%s flow_count=%s score=%.2f | src=%s -> RF verdict=%s",
                    dst_ip, flow_count, anomaly_score, src_ip,
                    "MALICIOUS" if prediction == 0 else "benign"
                )
                if prediction == 0 or anomaly_score >= 0.95:
                    reason = "RF" if prediction == 0 else "ADAPTIVE-OVERRIDE"
                    self.logger.info(
                        "[MITIGATION DECISION] src=%s reason=%s score=%.2f",
                        src_ip, reason, anomaly_score
                    )
                    self._mitigate(ev.msg.datapath, src_ip)

    def _compute_anomaly_score(self, dst_ip, flow_count):
        history = self.dst_history.setdefault(dst_ip, [])
        history.append(flow_count)
        if len(history) > 10:
            history.pop(0)
        avg = sum(history) / len(history)
        return min(avg / 100.0, 1.0)

    def _mitigate(self, datapath, src_ip):
        if src_ip in self.PROTECTED_IPS:
            self.logger.info("[SKIPPED] Refusing to mitigate protected IP %s", src_ip)
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=100, match=match, instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info("[MITIGATED] Drop rule installed for %s", src_ip)
