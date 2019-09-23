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


class Kurihara15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]
    #TCP_flags values
    TCP_SYN = 0x002
    TCP_RST = 0x004
    TCP_PSH = 0x008
    TCP_ACK = 0x010
    TCP_SYN_ACK = 0x012
    
    def __init__(self, *args, **kwargs):
        super(Kurihara15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
    # Create OFP flow mod message.
    def create_flow_mod(self, datapath, priority,
                        table_id, match, instructions):
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority,
                                match=match, instructions=instructions)
        return flow_mod
    # OVS adds new flow in table, "specs" must be array.
    def NXlearn_add_flow(self, datapath, priority,
                        table_id, specs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        flows = [parser.NXActionLearn(table_id=table_id,
         specs=specs,
         idle_timeout=180,
         hard_timeout=300,
         priority=priority,
         cookie=0x64,
         flags=ofproto.OFPFF_SEND_FLOW_REM,
         fin_idle_timeout=180,
         fin_hard_timeout=300)]
        
        return flows
    
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

        match = parser.OFPMatch()
        
        #Send packet to CONTROLLER
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #TableID:0
        self.add_flow(datapath, 0, match, actions)
        match_t1 = parser.OFPMatch(eth_type=0x0800, 
                                     ip_proto=6,
                                     tcp_flags=0x000)
        inst = [parser.OFPInstructionGotoTable(1)]
        datapath.send_msg(self.create_flow_mod(datapath, 1,0, match_t1, inst))
        #TableID:1
        actions1 =[parser.NXActionResubmitTable(in_port=0xfff8,table_id=10)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions1),
                parser.OFPInstructionGotoTable(2)]
        datapath.send_msg(self.create_flow_mod(datapath, 0,1, match, inst)) 
        #TableID:2
        datapath.send_msg(self.create_flow_mod(datapath, 1,2, 
                                               parser.OFPMatch(reg0=0), 
                                               [parser.OFPInstructionGotoTable(3)])) 
        datapath.send_msg(self.create_flow_mod(datapath, 0,2, 
                                               parser.OFPMatch(reg0=1), 
                                               [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)])) 
        #TableID:3
        #Match is nothing and set_field 1 -> reg0
        specs=[
            parser.NXFlowSpecMatch(src=0x800, dst=('eth_type_nxm', 0), n_bits=16),
            parser.NXFlowSpecLoad(src=1, dst=('reg0', 0), n_bits=5)
        ]
        flow10 = self.NXlearn_add_flow(datapath,1,10,specs)
        flow11 = self.NXlearn_add_flow(datapath,1,11,specs)
       
        actions1 =[parser.NXActionResubmitTable(in_port=0xfff8,table_id=11)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions1),
                parser.OFPInstructionGotoTable(4)]
        datapath.send_msg(self.create_flow_mod(datapath, 0,3, 
                                               parser.OFPMatch(eth_type=0x0800, 
                                     ip_proto=6,tcp_flags=self.TCP_RST),inst)) 
        # exchange IP,MAC,PORT
        actions1 =[parser.OFPActionCopyField(n_bits=32,oxm_ids=[parser.OFPOxmId('ipv4_src'), parser.OFPOxmId('reg1')]),
                   parser.OFPActionCopyField(n_bits=32,oxm_ids=[parser.OFPOxmId('ipv4_dst'), parser.OFPOxmId('ipv4_src')]),
                   parser.OFPActionCopyField(n_bits=32,oxm_ids=[parser.OFPOxmId('reg1'), parser.OFPOxmId('ipv4_dst')]),
                   parser.OFPActionCopyField(n_bits=48,oxm_ids=[parser.OFPOxmId('eth_src'), parser.OFPOxmId('xxreg3')]),
                   parser.OFPActionCopyField(n_bits=48,oxm_ids=[parser.OFPOxmId('eth_dst'), parser.OFPOxmId('eth_src')]),
                   parser.OFPActionCopyField(n_bits=48,oxm_ids=[parser.OFPOxmId('xxreg3'), parser.OFPOxmId('eth_dst')]),
                   parser.OFPActionCopyField(n_bits=16,oxm_ids=[parser.OFPOxmId('tcp_src'), parser.OFPOxmId('reg2')]),
                   parser.OFPActionCopyField(n_bits=16,oxm_ids=[parser.OFPOxmId('tcp_dst'), parser.OFPOxmId('tcp_src')]),
                   parser.OFPActionCopyField(n_bits=16,oxm_ids=[parser.OFPOxmId('reg2'), parser.OFPOxmId('tcp_dst')])
                   parser.OFPActionSetField(tcp_flags=self.TCP_SYN)
                  ]
                  
        actions1 += flow11
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions1)]
        datapath.send_msg(self.create_flow_mod(datapath, 1,3, 
                                               parser.OFPMatch(eth_type=0x0800, 
                                     ip_proto=6,tcp_flags=self.TCP_SYN),inst))
        
        #TableID:4
        datapath.send_msg(self.create_flow_mod(datapath, 1,4, 
                                               parser.OFPMatch(reg0=1), 
                                               [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             flow10)])) 
        #TableID:10
        actions1 = [parser.OFPActionSetField(reg0=0)]
        datapath.send_msg(self.create_flow_mod(datapath, 0,10, 
                                               parser.OFPMatch(), 
                                               [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions1)])) 
        #TableID:11
        datapath.send_msg(self.create_flow_mod(datapath, 0,11, 
                                               parser.OFPMatch(), 
                                               [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions1)])) 
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out)
