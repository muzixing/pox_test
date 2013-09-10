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

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

class pretend():
  def fake_1(self,event):
    inport = event.port
    packet = event.parsed
    # Try to forward
    dstaddr = packet.next.dstip
    #pretend to reply for a unknow ip
    print"packet in"
      #print isinstance(paceket.next.next,ARP) 
    if isinstance(packet.next.next,icmp):
          #EXCHANGE the ip  
        packet.next.dstip=packet.next.srcip
        packet.next.srcip=dstaddr
          #packet.next.port=packet.next.inport
        packet.next.next.type=0          
          #change the macaddress          
        print "pretend icmp"
        tmp=packet.dst
        packet.dst=packet.src
        packet.src=tmp
          #send it
        msg = of.ofp_packet_out()
        msg.data = packet
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = inport
        event.connection.send(msg)
        return

