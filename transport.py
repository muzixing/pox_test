# Copyright 2011,2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
A stupid L3 switch

For each switch:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpidToStr
from pox.lib.recoco import Timer
from pox.lib.packet.icmp import icmp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp


import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

class Transport():
  def deliver_1(self,event,dpid):
    #the table is used to change the trace
    self.dst_ip = {}
    
    inport = event.port
    packet = event.parsed
    proxy_server_ip=IPAddr("172.17.0.10")
    print type(proxy_server_ip)
    proxy_server_mac=EthAddr("00:22:19:12:37:1b")
    #if it is HTTP 
   
    #if it is a packet of tcp
    
    if isinstance(packet.next.next,tcp) and packet.next.next.dstport==80:
      log.debug("%i %i this is a http request packet" , dpid,inport)
      
      dstaddr = packet.next.dstip
      srcaddr = packet.next.srcip
      #it is a packet of tcp 
      print"tcp in"
      
      #self.tran_ip[(packet.src,packet.next.next.srcport)]=(inport,packet.next.dstip,packet.dst)

      self.dst_ip[(packet.src,packet.next.next.srcport)]=(inport,packet.next.dstip,packet.dst)	      
	    
      log.debug("%i %i this is a http request packet" , dpid,inport)      
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.actions.append(of.ofp_action_nw_addr.set_dst(proxy_server_ip))
      msg.actions.append(of.ofp_action_dl_addr.set_dst(proxy_server_mac))
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.idle_timeout = 10
      msg.hard_timeout = 30
      msg.buffer_id = event.ofp.buffer_id
      event.connection.send(msg)
      return
        #print"80"
      #if packet.srcaddr != proxy_server_ip:  
      #change the ip          packet.next.dstip=proxy_server_ip
      #change the macaddress
      #packet.dst=proxy_server_mac
      
      #send it
      #msg = of.ofp_packet_out()
      #msg.data = packet
      #msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      #msg.in_port = inport
      #event.connection.send(msg)
      #print "send http packet"
       # return
      #the pacekt back
    
    elif isinstance(packet.next.next,tcp) and packet.next.next.dstport ==80:
      log.debug("%i %i this is a http answer packet" , dpid,inport)
      if (packet.dst,packet.next.next.dstport) in self.tran_ip:
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.actions.append(of.ofp_action_nw_addr.set_src(self.dst_ip[(packet.dst,packet.next.next.dstport)][1]))
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.dst_ip[(packet.dst,packet.next.next.dstport)][2]))
        msg.actions.append(of.ofp_action_output(port = self.dst_ip[(packet.dst,packet.next.next.dstport)][0]))
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.buffer_id = event.ofp.buffer_id
        event.connection.send(msg)

        #it is a packet of tcp 
        #print"tcp back"
        #packet.next.dstip = self.tran_ip[(packet.dst,packet.next.next.dstport)][1]
        #packet.dst= self.tran_ip[(packet.dst,packet.next.next.dstport)][2]
        #send it
        #msg = of.ofp_packet_out()
        #msg.data = packet
        #msg.actions.append(of.ofp_action_output(port = self.tran_ip[(packet.dst,packet.next.next.dstport)][0]))
        #msg.in_port = inport
        #event.connection.send(msg)   
        return

