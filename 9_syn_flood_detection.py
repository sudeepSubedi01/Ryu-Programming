from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.lib.packet import ether_types


class MyRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyRyuApp, self).__init__(*args, **kwargs)
        print("----Ryu app has started----")

        self.packet_count = {}
        self.syn_count = {}
        self.blocked_hosts = set()

    # TABLE-MISS FLOW (SEND TO CONTROLLER)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        print("----Switch connected----")

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )

        datapath.send_msg(flow)

    # PACKET-IN HANDLER (IDS + SYN FLOOD)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # Drop if already blocked
        if src_mac in self.blocked_hosts:
            return

        # GENERIC PACKET COUNT
        self.packet_count[src_mac] = self.packet_count.get(src_mac, 0) + 1
        print(f"[INFO] Packet from {src_mac}, total = {self.packet_count[src_mac]}")

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # SYN FLOOD DETECTION
        if ip_pkt and tcp_pkt:
            # SYN = 1 and ACK = 0
            if (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK):
                self.syn_count[src_mac] = self.syn_count.get(src_mac, 0) + 1
                print(f"[INFO] SYN from {src_mac}, count = {self.syn_count[src_mac]}")

                SYN_THRESHOLD = 10
                if self.syn_count[src_mac] > SYN_THRESHOLD:
                    print(f"[ALERT] SYN Flood detected from {src_mac}")
                    print(f"[IDS] Installing drop rule...")

                    match = parser.OFPMatch(eth_src=src_mac)
                    flow = parser.OFPFlowMod(
                        datapath=datapath,
                        priority=100,
                        match=match,
                        instructions=[]
                    )

                    datapath.send_msg(flow)
                    self.blocked_hosts.add(src_mac)

                    print(f"[IDS] Host {src_mac} blocked")
                    return

        # -------------------------------
        # NORMAL FORWARDING (FLOOD)
        # -------------------------------
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)
        ]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)
