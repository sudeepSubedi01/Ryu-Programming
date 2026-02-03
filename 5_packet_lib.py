from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
# Packet Library for Parsing
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import arp

class MyRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyRyuApp, self).__init__(*args, **kwargs)
        print("----Ryu app started----")


    # Switch connected -> table-miss
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        print("----Switch connected----")

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow
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

    # Handle Packet-In messages
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg                        # msg = contains the Packet-In OpenFlow message; msg.data = actual packet as raw bytes
        datapath = msg.datapath             # datapath = the switch that sent it
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']      # in_port = the port on the switch where the packet came from

        # Parse raw bytes and store them internally
        pkt = packet.Packet(msg.data)
        # print("----pkt----")
        # print(pkt)

        eth = pkt.get_protocol(ethernet.ethernet)
        print("----eth----")
        print(eth)
        # if eth:
        #     src_mac = eth.src               # source mac
        #     dst_mac = eth.dst               # destination mac
        #     print(f"Ethernet Packet: {src_mac} -> {dst_mac} on port {in_port}")

        # ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # if ip_pkt:
        #     print(f"IPv4 Packet: {ip_pkt.src} -> {ip_pkt.dst}")

        # arp_pkt = pkt.get_protocol(arp.arp)
        # if arp_pkt:
        #     print(f"ARP Packet: {arp_pkt.src_ip} -> {arp_pkt.dst_ip}")

