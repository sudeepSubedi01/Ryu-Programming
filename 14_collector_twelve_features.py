from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub
import csv
import time

class NIDSCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NIDSCollector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.label = 0  # 0 for Normal, 1 for Attack
        
        # flow_tracker stores: { flow_key: [stats_dict] }
        # flow_key: (src_ip, dst_ip, protocol, src_port, dst_port)
        self.flow_tracker = {} 
        
        # Create CSV and write headers if it doesn't exist
        with open('14_dataset.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "Flow Byts/s",
                "SYN Flag Cnt", "ACK Flag Cnt", "PSH Flag Cnt", "RST Flag Cnt",
                "Flow Pkts/s", "Pkt Len Mean", "Flow IAT Mean", "Protocol", "Label"
            ])
        
        self.monitor_thread = hub.spawn(self._flush_to_csv)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        # Send full packet to controller for inspection
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.datapaths[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions):
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # --- FEATURE EXTRACTION BLOCK ---
        iph = pkt.get_protocol(ipv4.ipv4)
        if iph:
            src_ip = iph.src
            dst_ip = iph.dst
            proto = iph.proto
            sport, dport = 0, 0
            
            # TCP/UDP parsing
            tcph = pkt.get_protocol(tcp.tcp)
            udph = pkt.get_protocol(udp.udp)
            
            flags = {'syn': 0, 'ack': 0, 'psh': 0, 'rst': 0}
            if tcph:
                sport, dport = tcph.src_port, tcph.dst_port
                if tcph.bits & tcp.TCP_SYN: flags['syn'] = 1
                if tcph.bits & tcp.TCP_ACK: flags['ack'] = 1
                if tcph.bits & tcp.TCP_PSH: flags['psh'] = 1
                if tcph.bits & tcp.TCP_RST: flags['rst'] = 1
            elif udph:
                sport, dport = udph.src_port, udph.dst_port

            # Create bi-directional key (sort IPs so A->B and B->A are same flow)
            flow_key = tuple(sorted((src_ip, dst_ip))) + (proto, sport, dport)
            now = time.time()
            
            if flow_key not in self.flow_tracker:
                self.flow_tracker[flow_key] = {
                    'start': now, 'last': now, 'fwd': 1, 'bwd': 0,
                    'bytes': len(msg.data), 'syn': flags['syn'], 'ack': flags['ack'],
                    'psh': flags['psh'], 'rst': flags['rst'], 'iat_sum': 0, 'proto': proto
                }
            else:
                f = self.flow_tracker[flow_key]
                f['fwd'] += 1 if src_ip == flow_key[0] else 0
                f['bwd'] += 1 if src_ip == flow_key[1] else 0
                f['bytes'] += len(msg.data)
                f['iat_sum'] += (now - f['last'])
                f['syn'] += flags['syn']
                f['ack'] += flags['ack']
                f['psh'] += flags['psh']
                f['rst'] += flags['rst']
                f['last'] = now

        # --- SWITCHING LOGIC ---
        dst, src = eth.dst, eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, datapath.ofproto.OFPP_FLOOD)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        
        # Note: We do NOT install a flow here to keep packets coming to controller
        # for real-time feature extraction.
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)

    def _flush_to_csv(self):
        """Periodically calculates final features and writes to CSV"""
        while True:
            hub.sleep(10)
            if not self.flow_tracker: continue
            
            with open('14_dataset.csv', 'a') as f:
                writer = csv.writer(f)
                # Work on a copy to avoid dictionary size change during iteration
                for key, data in list(self.flow_tracker.items()):
                    duration = data['last'] - data['start']
                    if duration == 0: duration = 0.001 # Avoid div by zero
                    
                    tot_pkts = data['fwd'] + data['bwd']
                    writer.writerow([
                        round(duration, 4),      # Flow Duration
                        data['fwd'],             # Tot Fwd Pkts
                        data['bwd'],             # Tot Bwd Pkts
                        round(data['bytes']/duration, 2), # Flow Byts/s
                        data['syn'],             # SYN Flag Cnt
                        data['ack'],             # ACK Flag Cnt
                        data['psh'],             # PSH Flag Cnt
                        data['rst'],             # RST Flag Cnt
                        round(tot_pkts/duration, 2),      # Flow Pkts/s
                        round(data['bytes']/tot_pkts, 2), # Pkt Len Mean
                        round(data['iat_sum']/tot_pkts, 4) if tot_pkts > 1 else 0, # IAT Mean
                        data['proto'],           # Protocol
                        self.label               # Label
                    ])
            self.flow_tracker.clear() # Clear memory after writing