from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.addresses import IPAddr,EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp
from pox.lib.revent.pretend import pretend
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0


#__________________________________________________________
# You just need to change this part and the l2_learning class. 
special_sw=0x0000000000000001
CACHE_IP=IPAddr('172.16.0.1')
CACHE_MAC=EthAddr('00:1b:21:85:88:0b')
Assigned_IP=IPAddr('192.168.0.2')
#You need to fix the special ip. 
#__________________________________________________________




class LearningSwitch (object):
 
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed
    inport = event.port
    dpid = event.connection.dpid
    #print packet.next
    

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
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
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        print"what?"
        self.connection.send(msg)

class LearningSwitch1 (object):
 
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}
    self.dst_ip={}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed
    inport = event.port
    dpid = event.connection.dpid
#_________________________________________________
    #if isinstance(packet.next, ipv4):
      #dstaddr = packet.next.dstip
      #icmp_test=pretend()
      #icmp_test.fake_1(event)
      #print"pretend"
#_________________________________________________
    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...
        

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      print"drop"
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        #msg.match.dl_src = packet.src
        #msg.match.dl_dst = packet.dst
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
      
        return

    # hosts send http request to origion server -- change dst to nginx
    # nginx send http request to origion server -- do not change anything
    if hasattr(packet.next,'next') and isinstance(packet.next.next, tcp) and packet.next.next.dstport == 80 \
        and not packet.src == CACHE_MAC and packet.next.srcip == Assigned_IP:#the special IP can work!
        self.dst_ip[(packet.src,packet.next.next.srcport)]=(inport,packet.next.dstip,packet.dst)      
        log.debug("%i %i this is a http request packet" , dpid,inport)
            
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.actions.append(of.ofp_action_nw_addr.set_dst(CACHE_IP))
        #msg.actions.append(of.ofp_action_dl_addr.set_dst(CACHE_MAC))
        if CACHE_MAC in self.macToPort:
          special_port= self.macToPort[CACHE_MAC]
          msg.actions.append(of.ofp_action_output(port = special_port)) 
        else:
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))      
        msg.idle_timeout = 10     
        msg.hard_timeout = 30
        #msg.buffer_id = event.ofp.buffer_id   
        msg.data = event.ofp
        self.connection.send(msg)
        print "Receive the HTTP request from special IP"  
        return

    # nginx send http ack back to host -- change src to origion server
    # origion server send http ack to nginx -- do not change any thing		 
    elif hasattr(packet.next,'next') and isinstance(packet.next.next, tcp) and packet.next.next.srcport==80\
        and not packet.dst == CACHE_MAC and  packet.next.dstip == Assigned_IP:         
        log.debug("%i %i this is a http answer packet" , dpid,inport)
        print "Nginx Reply to the host"
        if (packet.dst,packet.next.next.dstport) in self.dst_ip:
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet)
          msg.actions.append(of.ofp_action_nw_addr.set_src(self.dst_ip[(packet.dst,packet.next.next.dstport)][1]))
          msg.actions.append(of.ofp_action_dl_addr.set_src(self.dst_ip[(packet.dst,packet.next.next.dstport)][2]))
          msg.actions.append(of.ofp_action_output(port = self.dst_ip[(packet.dst,packet.next.next.dstport)][0]))
          msg.idle_timeout = 10
          msg.hard_timeout = 30
          #msg.buffer_id = event.ofp.buffer_id 
          msg.data = event.ofp
          self.connection.send(msg)
          print"It has done!"
          return 

    else:
      if packet.dst.is_multicast:
        flood() # 3a
      else:
        if packet.dst not in self.macToPort: # 4
          flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
        else:
          port = self.macToPort[packet.dst]
          if port == event.port: # 5
            # 5a
            log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
                % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
            drop(10)
            return
          # 6
          log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet)
          #msg.match.dl_src = packet.src
          #msg.match.dl_dst = packet.dst
          msg.idle_timeout = 10
          msg.hard_timeout = 30
          msg.actions.append(of.ofp_action_output(port = port))
          msg.data = event.ofp # 6a
          self.connection.send(msg)


class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    #_______________________________________________________
    if event.dpid==special_sw:
      LearningSwitch1(event.connection, self.transparent) 
    else: 
      LearningSwitch(event.connection, self.transparent)
    #_______________________________________________________


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))
