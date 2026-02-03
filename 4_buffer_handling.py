from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3


class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    # Flow Miss Handler
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        print("----Switch connected----")

        datapath = ev.msg.datapath          # datapath represents the connected switch
        ofproto = datapath.ofproto          # Shortcut to OpenFlow constants
        parser = datapath.ofproto_parser    # OpenFlow message factory, used to construct Matches, Actions, Instructions, FlowMod Messages

        # TABLE-MISS FLOW
        match = parser.OFPMatch()   # Empty match = match all packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,      # List of actions to specify where the packets should go in case of match
                                          ofproto.OFPCML_NO_BUFFER)]    # 1. Special OF Port (send packet to controller), 2. Send the entire packet

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,   # Instruction list to apply actions
                                             actions)]                      # Executes the given action immediately (by switch)

        mod = parser.OFPFlowMod(datapath=datapath,      # Creates a FlowMod Msg; Specifies which switch is this rule for
                                priority=0,             # Lowest priority (Any packet that doesn’t match a higher-priority flow triggers this)
                                match=match,            # match everything
                                instructions=inst)      # send packet to the controller

        datapath.send_msg(mod)              # Sends FlowMod msg to the switch; Switch installs the table-miss rule
        # Now: Any unmatched packet → Packet-In → controller

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
