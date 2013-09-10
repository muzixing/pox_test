#this file is to solve the muticast strom.

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.icmp import icmp
from pox.lib.revent import *


class Anti_broadcast():
	"""docstring for Anti_muticast"""
	def __init__(self, event,TimeToArrive,macToPort):
		self.event = event
		#USE THIS TABLE TO RECORD THE MUTICAST PACKET'S IP AND INPORT
		#our table match specified arp packet{srcMac:[dstip,port,time]}
		self.packetToPort={}
		self.TimeToArrive =TimeToArrive
    	self.macToPort=macToPort
    	#_________________________________________________________________________________________
	def Anti_broadcast(self,event,TimeToArrive,macToPort):
		packet = event.parse()
		inport = event.port
		dpid   = event.connection.dpid
		if isinstance(packet.next,arp) and (packet.next.opcode == arp.REQUEST):
			if (packet.next.hwsrc in self.packetToPort) and (packet.next.protodst ==self.packetToPort[packet.src][0]):#if the flow table is exist,then flood under this rule.
				if(inport != self.packetToPort[packet.src][1]):
					drop()#if not the specially inport,then drop it.
					print("the same muticast packet form other inport ,just drop it")
					return
				else:
					flood("Another muticast packet form the port %s -- flooding,we set limit_time to drop it "%(packet.src))
					print("Another muticast packet form %s at %i port in %i "%(packet.src,inport,dpid))
					return
			else:#the record don't exist,then learn it .
				self.packetToPort[packet.src]=[packet.next.protodst,inport,TimeToArrive]#record and lock the port
				self.macToPort[packet.src]=[inport,TimeToArrive]#update the L2 table.
				print("update the table entry of %s at %i in %i ,"%(packet.src,inport,dpid))
				flood()
		return
#_________________________________________________________________________________________
		
