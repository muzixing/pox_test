from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.addresses import IPAddr,EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.revent.pretend import pretend
from pox.lib.packet.arp import arp
#from pox.lib.revent.Anti_broadcast import Anti_broadcast
from pox.lib.packet.icmp import icmp
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 5


special_sw=4
special_cache=9
CACHE_IP=IPAddr('172.16.0.1')
CACHE_MAC=EthAddr('00:22:19:12:37:1b')


class LearningSwitch (EventMixin):
  
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}
      #USE THIS TABLE TO RECORD THE MUTICAST PACKET'S IP AND INPORT
    #our table match specified arp packet{srcMac:[dstip,port,time]}
    self.packetToPort={}

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))
    

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    print"packet in"
    packet = event.parse()
    inport = event.port
    dpid = event.connection.dpid
    TimeToArrive = time.time()   
    

    def flood ():
      print"flood"
      """ Floods the packet """
      if event.ofp.buffer_id == -1:
        log.warning("Not flooding unbuffered packet on %s",
                    dpidToStr(event.dpid))
        return
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time > FLOOD_DELAY:
        # Only flood if we've been connected for a little while...
        #log.debug("%i: flood %s -> %s", event.dpid, packet.src, packet.dst)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpidToStr(event.dpid))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      print"drop"
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id != -1:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent:
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered(): # 2
        drop()
        return
#______________________________________________
    if packet.dst.isMulticast():
      if isinstance(packet.next,arp) and (packet.next.opcode == arp.REQUEST):
        if (packet.next.hwsrc in self.packetToPort) and (packet.next.protodst ==self.packetToPort[packet.src][0]):
        #if the flow table is exist,then flood under this rule.
          if(inport != self.packetToPort[packet.src][1]):
            drop()#if not the specially inport,then drop it.
            print("the same muticast packet form other inport ,just drop it")
            return
          else:
            flood()
            print("Another muticast packet form %s at %i port in %i "%(packet.src,inport,dpid))
            return
        else:#the record don't exist,then learn it .
          self.packetToPort[packet.src]=[packet.next.protodst,inport,TimeToArrive]#record and lock the port
          self.macToPort[packet.src]=[inport,TimeToArrive]#update the L2 table.
          print("update the table entry of %s at %i in %i ,"%(packet.src,inport,dpid))
          flood()
      return
      #broadcast=Anti_broadcast(event,TimeToArrive,macToPort)
      #broadcast.Anti_broadcast(event,TimeToArrive,macToPort)
      #flood() # 3a    #we try to solve the broadcast storm.
#____________________________________________________
    else:
      if packet.dst not in self.macToPort: # 4
        log.debug("Port for %s unknown -- flooding" % (packet.dst,))
        flood() # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.  Drop." %
                      (packet.src, packet.dst, port), dpidToStr(event.dpid))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.buffer_id = event.ofp.buffer_id
        #msg.data = event.ofp # 6a
        self.connection.send(msg)

class LearningSwitch1 (EventMixin):
  
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}
    self.dst_ip={} 

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    inport = event.port
    dpid = event.connection.dpid
    print"handlle_packetin"
    #if isinstance(packet.next, ipv4):
      #dstaddr = packet.next.dstip
      #icmp_test=pretend()
      #icmp_test.fake_1(event)
      #print"pretend"

    def flood ():
      """ Floods the packet """
      if event.ofp.buffer_id == -1:
        log.warning("Not flooding unbuffered packet on %s",
                    dpidToStr(event.dpid))
        return
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time > FLOOD_DELAY:
        # Only flood if we've been connected for a little while...
        #log.debug("%i: flood %s -> %s", event.dpid, packet.src, packet.dst)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpidToStr(event.dpid))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id != -1:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent:
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered(): # 2
        drop()
        print"drop"
        returns
    print"judge"
   
    #print packet.next.srcip
    if hasattr(packet.next,'next') and isinstance(packet.next.next, tcp)and packet.next.next.dstport==80:
      self.dst_ip[(packet.src,packet.next.next.srcport)]=(inport,packet.next.dstip,packet.dst)
      log.debug("%i %i this is a http request packet" , dpid,inport)
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.actions.append(of.ofp_action_nw_addr.set_dst(CACHE_IP))
      msg.actions.append(of.ofp_action_dl_addr.set_dst(CACHE_MAC))
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      #msg.actions.append(of.ofp_action_output(port = special_cache))
      msg.idle_timeout = 10
      msg.hard_timeout = 30
      msg.buffer_id = event.ofp.buffer_id
      print"I am successful!"
      self.connection.send(msg)
      return
    elif hasattr(packet.next,'next') and isinstance(packet.next.next, tcp)and packet.next.next.srcport==80:
      log.debug("%i %i this is a http answer packet" , dpid,inport)
      if (packet.dst,packet.next.next.dstport) in self.dst_ip:
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.actions.append(of.ofp_action_nw_addr.set_src(self.dst_ip[(packet.dst,packet.next.next.dstport)][1]))
        msg.actions.append(of.ofp_action_dl_addr.set_src(self.dst_ip[(packet.dst,packet.next.next.dstport)][2]))
        msg.actions.append(of.ofp_action_output(port = self.dst_ip[(packet.dst,packet.next.next.dstport)][0]))
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.buffer_id = event.ofp.buffer_id
        print"fanhui de"
        self.connection.send(msg)
        return 
    else:
      if packet.dst.isMulticast():
        flood() # 3a
      else:
        if packet.dst not in self.macToPort: # 4
          log.debug("Port for %s unknown -- flooding" % (packet.dst,))
          flood() # 4a
        else:
          port = self.macToPort[packet.dst]
          if port == event.port: # 5
          # 5a
            log.warning("Same port for packet from %s -> %s on %s.  Drop." %
                      (packet.src, packet.dst, port), dpidToStr(event.dpid))
            drop(10)
            return
        # 6
          log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet)
          msg.idle_timeout = 10
          msg.hard_timeout = 30
          msg.actions.append(of.ofp_action_output(port = port))
          msg.buffer_id = event.ofp.buffer_id
          self.connection.send(msg)

class l2_learning (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    self.listenTo(core.openflow)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    if event.dpid==special_sw:
      LearningSwitch1(event.connection, self.transparent) 
    else: 
      LearningSwitch(event.connection, self.transparent)
      #change1


def launch (transparent=False):
  """
  Starts an L2 learning switch.
  """
  core.registerNew(l2_learning, str_to_bool(transparent))
