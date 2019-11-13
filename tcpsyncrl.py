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

# Original file is simple_switch_15.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class TCPSYN13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]
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
        # msgはpacket_inのメッセージ
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        # スイッチを特定するためのデータパスIDを取得
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # フラッディングパケットは送信元ポート以外に送信される
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # Flow modが実施されている
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)
        # これはFlow modではなくパケットの値をFloodするようにPacket_outしているだけ
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out)
