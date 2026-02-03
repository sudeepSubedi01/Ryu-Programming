from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3


class MyFirstRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyFirstRyuApp, self).__init__(*args, **kwargs)
        print("----Ryu app started----")

    # Flow Miss Handler
    # Switch connected -> table-miss
    # This runs once per switch to install a 'policy' that says "If you dont know what to do with the packet, send it to the controller."
    # Then next time if the policy for a packet doesnt exist in the switch, it sends the packet to the controller and this triggers events.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        print("----Switch connected----")

        msg = ev.msg
        datapath = msg.datapath          # datapath represents the connected switch
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
    
    # Detect/Handle Packet-In Messages
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print("----Packet-In received at controller----")
