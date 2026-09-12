from os_ken.controller.handler import CONFIG_DISPATCHER
from os_ken.lib.packet import ethernet, ether_types

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet
import joblib
import os

class HybridDDoSController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ---- your paper's threshold T ----
    ANOMALY_THRESHOLD = 0.6
    POLL_INTERVAL = 5  # seconds

    def __init__(self, *args, **kwargs):
        self.mac_to_port = {}
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        model_path = os.path.join(os.path.dirname(__file__), "model_RF.pkl")
        self.model = joblib.load(model_path)
        self.flow_history = {}  # src_ip -> list of packet counts
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif dp.id in self.datapaths:
            del self.datapaths[dp.id]

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
        for stat in ev.msg.body:
            match = stat.match
            src_ip = match.get('ipv4_src')
            if not src_ip:
                continue

            packet_count = stat.packet_count
            byte_count = stat.byte_count
            duration = stat.duration_sec + stat.duration_nsec / 1e9

            # ---------------- STAGE 1: Adaptive layer (cheap) ----------------
            anomaly_score = self._compute_anomaly_score(src_ip, packet_count)

            if anomaly_score <= self.ANOMALY_THRESHOLD:
                continue

            # ---------------- STAGE 2: AI layer (gated) ------------
            features = [[packet_count, byte_count, duration]]
            prediction = self.model.predict(features)[0]  # 1 = legit, 0 = malicious

            self.logger.info(
                "[GATE TRIGGERED] src=%s score=%.2f pkt=%s -> RF verdict=%s",
                src_ip, anomaly_score, packet_count,
                "MALICIOUS" if prediction == 0 else "benign"
            )

            if prediction == 0:
                self._mitigate(ev.msg.datapath, src_ip)

    def _compute_anomaly_score(self, src_ip, packet_count):
        history = self.flow_history.setdefault(src_ip, [])
        history.append(packet_count)
        if len(history) > 10:
            history.pop(0)
        avg = sum(history) / len(history)
        score = min(avg / 1000.0, 1.0)
        return score

    def _mitigate(self, datapath, src_ip):
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
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss flow entry: send unmatched packets to controller
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
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=1,
                                     match=match, instructions=inst)
            datapath.send_msg(mod)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
