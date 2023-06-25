from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr,IP_ANY
from collections import namedtuple
import os
''' New imports here ... '''
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST,ETHER_ANY
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

import time
log = core.getLogger()
priority = 50000

class Firewall (EventMixin):

        def __init__ (self):
		self.listenTo(core.openflow)
		self.fwconfig = list()
                self.ptbl = {}

	def installFlow(self, event, offset, inport, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
                match.in_port=inport
		if(srcip != None):
			match.nw_src = IPAddr(srcip)
		if(dstip != None):
			match.nw_dst = IPAddr(dstip)	
		match.nw_proto = int(nwproto)
		match.dl_src = srcmac
		match.dl_dst = dstmac
		match.tp_src = sport
		match.tp_dst = dport
		match.dl_type = pkt.ethernet.IP_TYPE
		msg.match = match
		msg.hard_timeout = of.OFP_FLOW_PERMANENT
		msg.idle_timeout = of.OFP_FLOW_PERMANENT #200
		msg.priority = priority + offset		
		event.connection.send(msg)

	def _handle_PacketIn(self, event):
		packet = event.parsed
                inport = event.port
		match = of.ofp_match.from_packet(packet,inport)

		if(match.dl_type == packet.IP_TYPE):
		  ip_packet = packet.payload
		  print "Ip_packet.protocol = ", ip_packet.protocol
		  if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
			log.debug("TCP it is !")
                        tcppkt = ip_packet.payload
                        print tcppkt.SYN,tcppkt.flags,inport
                        if tcppkt.SYN:
                            if not inport in self.ptbl:
                                self.ptbl[inport]=[match.nw_src]
                            else:
                                self.ptbl[inport].append(match.nw_src)
                            print self.ptbl
                            if len(self.ptbl[inport])>5:
                                #print "not issuing any rule"
                                self.installFlow(event, 1, inport,
                                        None, match.dl_dst, 
                                        None, match.nw_dst, 
                                        None, None, match.nw_proto)
                                self.ptbl={}
   
def launch ():
	'''
	Starting the Firewall module
	'''
	core.registerNew(Firewall)
