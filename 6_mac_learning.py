from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class MyRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__ (self, *args, **kwargs):
        super(MyRyuApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        print("----Ryu App has started----")
    
    # Table miss flow handler
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        print("----Switch connected----")

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=match,
                                instructions=inst)
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

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # LEARNING STEP
        self.mac_to_port[dpid][src] = in_port
        print(f"Learned MAC {src} on port {in_port}")

        # FORWARDING DECISION
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print(f"Known destination {dst}, forward to port {out_port}")
        else:
            out_port = ofproto.OFPP_FLOOD           # if dst mac is not learned, flood the packet
            print(f"Unknown destination {dst}, flooding")

        actions = [parser.OFPActionOutput(out_port)]

        # INSTALL FLOW RULE (only if not flooding)
        if out_port != ofproto.OFPP_FLOOD:      # flooding is temporary behaviour
            match = parser.OFPMatch(            # creating a match for future packets. Its applied/used only when eth_dst = dst (from above) && in_port = in_port (from above)
                in_port=in_port,
                eth_dst=dst
            )

            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=1,
                match=match,
                instructions=inst
            )

            datapath.send_msg(mod)

        # SEND CURRENT PACKET
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