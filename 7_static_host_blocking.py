from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

# STATIC HOST BLOCKING

# The Topology
# h1 (mac1) ------(port1) s1
# h2 (mac2) ------(port2) s1
# h3 (mac3) ------(port3) s1

# h3 is suspicious
# h3 -> h1, h2 (blocked)
# h1, h2 -> h3 (blocked)
# h1 <-> h2 (allowed)
# The rule that blocks: h3 -> h1,h2; will also block: h1,h2 -> h3

class MyRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyRyuApp, self).__init__(*args, **kwargs)
        print("----Ryu app started----")
    
    # Switch connected -> table-miss
    # Table-Miss Handling
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        print("----Switch connected----")

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Static Blocking
        blocked_mac = "da:46:9d:38:38:2a"
        block_match = parser.OFPMatch(eth_src=blocked_mac)
        block_inst = []                                     # No actions = DROP
        block_flow = parser.OFPFlowMod(datapath=datapath,
                                       priority=100,        # Higher than table-miss
                                       match=block_match,
                                       instructions=block_inst)
        datapath.send_msg(block_flow)
        print("----Blocking rule installed for h3----")

        # Table-miss flow
        miss_match = parser.OFPMatch()
        miss_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        miss_inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             miss_actions)]
        
        miss_flow = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=miss_match,
                                instructions=miss_inst)
        datapath.send_msg(miss_flow)

    # BUFFER HANDLING
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']      # The input port for the packet

        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)      # Flood packet to all ports except the input one
        ]

        # BUFFER HANDLING: 
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,            # Prevents sending packet back to same port
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

    
