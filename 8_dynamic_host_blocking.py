from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class MyRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyRyuApp, self).__init__(*args, **kwargs)
        print("----Ryu app has started----")

        # Count packets per source MAC
        self.packet_count={}
        # Keep track of already blocked hosts
        self.blocked_hosts = set()
    
    # Table-Miss Handling
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self,ev):
        print("----Switch connected----")

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        ins = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=match,
                                instructions=ins)
        datapath.send_msg(mod)

    # Packet-In Handling (Dynamic IDS Logic)
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
        
        src_mac = eth.src
        dst_mac = eth.dst

        if src_mac in self.blocked_hosts:
            return
        
        self.packet_count[src_mac] = self.packet_count.get(src_mac,0) + 1 
        print(f"[INFO] Packet from {src_mac}, count = {self.packet_count[src_mac]}")

        THRESHOLD = 7
        if self.packet_count[src_mac] > THRESHOLD:
            print(f"[ALERT] {src_mac} detected as suspicious. Blocking...")

            block_match = parser.OFPMatch(eth_src=src_mac)
            block_ins = []
            block_flow = parser.OFPFlowMod(datapath=datapath,
                                           priority=100,
                                           match=block_match,
                                           instructions=block_ins)
            datapath.send_msg(block_flow)
            self.blocked_hosts.add(src_mac)
            print(f"[IDS] Dynamic block installed for {src_mac}")
            return

        # NORMAL FORWARDING IF NOT SUSPICIOUS
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)
        ]

        # BUFFER HANDLING: 
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