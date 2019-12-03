# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Original file is simple_switch_13.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class TCPSYN13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #TCP_flags values
    TCP_SYN = 0x002
    TCP_RST = 0x004
    TCP_PSH = 0x008
    TCP_ACK = 0x010
    TCP_SYN_ACK = 0x012
    
    def __init__(self, *args, **kwargs):
        super(TCPSYN13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
    # Create OFP flow mod message.
    def create_flow_mod(self, datapath, priority,
                        table_id, match, instructions):
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority,
                                match=match, instructions=instructions)
        return flow_mod
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #Send packet to CONTROLLER
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #TableID:0 INGRESS_FILTERING
        match_t1 = parser.OFPMatch(eth_type=0x0800, 
                                     ip_proto=6)
        inst = [parser.OFPInstructionGotoTable(1)]
        datapath.send_msg(self.create_flow_mod(datapath,2,0,match_t1,inst))
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(4)]
        datapath.send_msg(self.create_flow_mod(datapath,1,0,match,inst))
   
        #TableID:1 CHECKED_TCP
        inst = [parser.OFPInstructionGotoTable(2)]
        datapath.send_msg(self.create_flow_mod(datapath,1,1,match,inst))
        
        #TableID:2 CHECKING_TCP
        inst = [parser.OFPInstructionGotoTable(3)]
        datapath.send_msg(self.create_flow_mod(datapath,1,2,match,inst)) 
       
        #TableID:3 UNCHECK_TCP
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(self.create_flow_mod(datapath,1,3,match,inst)) 
     
        #TableID:4 FORWARDING
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(self.create_flow_mod(datapath,1,4,match,inst)) 

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        self.logger.info("packet-in %s" % (pkt,))
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            self._handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, pkt_tcp)
            return

    def _handle_tcp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_tcp):
        pkt_in = packet.Packet()

        # Mac in received pkt
        pkt_in.add_protocol(
            ethernet.ethernet(
                dst=pkt_ethernet.src,
                src=pkt_ethernet.dst,
            ),
        ) 
        # IP in received pkt
        pkt_in.add_protocol(
            ipv4.ipv4(
                dst=pkt_ipv4.src,
                src=pkt_ipv4.dst,
                proto=in_proto.IPPROTO_TCP,
            ),
        )
        # Port , Seq , Ack and Flags in received pkt
        pkt_in.add_protocol(
            tcp.tcp(
                src_port=pkt_tcp.dst,
                dst_port=pkt_tcp.src,
            ),
         )
        payload_data = b'arbitrary'  # as a raw binary
        pkt_in.add_protocol(payload_data)
        self.send_packet(datapath,port,pkt_in)
        
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
