"""
@author: Tara Saba
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr,IPAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import echo, icmp
import pox.lib.packet as pkt
log = core.getLogger()

class Router(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.mac_to_port ={}
        self.arp_set ={}
        self.ip_to_mac={
            '10.0.1.1': '00:00:00:00:00:11',
            '10.0.2.1': '00:00:00:00:00:22',
            '10.0.3.1': '00:00:00:00:00:33'
        }

        self.routing_table= {
            '10.0.1.0/24': {'host': '10.0.1.100','port': 1 , 'gateway': '10.0.1.1'},
            '10.0.2.0/24': {'host': '10.0.2.100', 'port': 2, 'gateway': '10.0.2.1'},
            '10.0.3.0/24': {'host': '10.0.3.100', 'port': 3, 'gateway': '10.0.3.1'},
        }

        #static
        for address in self.ip_to_mac.keys():
            fm =of.ofp_flow_mod()
            fm.match._dl_type =ethernet.IP_TYPE
            fm.match.nw_dst = IPAddr(address)
            fm.match.nw_proto = ipv4.ICMP_PROTOCOL
            fm.idle_timeout = 300
            fm.priority = 2
            print(address)
            fm.actions.append(of.ofp_action_output(port= of.OFPP_CONTROLLER)) #action = send to controller
            self.connection.send(fm)

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)
    def ARP_packet(self, packet, packet_in):
        arp_pay = packet.payload
        #constructing arp replies
        if arp_pay.opcode == arp.REQUEST:
            requested_ip = str(arp_pay.protodst)
            if requested_ip in self.ip_to_mac:
                reply_message = arp()
                reply_message.opcode= arp.REPLY
                reply_message.protodst = arp_pay.protosrc
                reply_message.protosrc = arp_pay.protodst
                reply_message.hwdst = arp_pay.hwsrc
                reply_message.hwsrc = EthAddr(self.ip_to_mac[requested_ip])
                ethernet_frame =ethernet()
                ethernet_frame.payload = reply_message
                ethernet_frame.src = EthAddr(self.ip_to_mac[requested_ip])
                ethernet_frame.dst = arp_pay.hwsrc
                ethernet_frame.type = ethernet.ARP_TYPE

                self.resend_packet(ethernet_frame, packet_in.in_port)

        elif arp_pay.opcode ==arp.REPLY:
            new_physical_address= str(arp_pay.hwsrc)
            replying_ip = str(arp_pay.protosrc)
            if replying_ip not in self.ip_to_mac:
                self.ip_to_mac[replying_ip] =new_physical_address
                if new_physical_address not in self.mac_to_port:
                    self.mac_to_port[new_physical_address] = packet_in.in_port
            #related to construction of the arp request
            if replying_ip in self.arp_set.keys():
                self.sendIPv4(replying_ip)


                self.arp_set.pop(replying_ip)

    def sendIPv4(self, destination):
        arp_datagram = self.arp_set[destination][1]
        ethernet_frame = ethernet()
        ethernet_frame.payload = arp_datagram
        destination_network = self.arp_set[destination][0]
        ethernet_frame.src = EthAddr(self.ip_to_mac[self.routing_table[destination_network]['gateway']])
        ethernet_frame.dst = EthAddr(self.ip_to_mac[destination])
        ethernet_frame.type = ethernet.IP_TYPE

        out_port = self.routing_table[destination_network]['port']
        self.resend_packet(ethernet_frame,out_port)

    def ICMP_packet(self, packet,packet_in):

        icmp_packet = packet.payload.payload
        if icmp_packet.type == 8 : #TYPE_ECHO_REQUEST won't workkkk
            reply_message = icmp()
            reply_message.type = 0
            reply_message.payload =icmp_packet.payload
            reply_message.code = 0
            ipv4_datagram = ipv4()
            received_datagram = packet.payload
            ipv4_datagram.payload = reply_message
            ipv4_datagram.dstip = received_datagram.srcip
            ipv4_datagram.srcip = received_datagram.dstip
            ipv4_datagram.protocol = ipv4.ICMP_PROTOCOL
            ethernet_frame = ethernet()
            ethernet_frame.payload = ipv4_datagram
            ethernet_frame.src = packet.dst
            ethernet_frame.dst = packet.src
            ethernet_frame.type = ethernet.IP_TYPE

            self.resend_packet(ethernet_frame,packet_in.in_port)

    def dest_unreachable(self, packet, packet_in):

        reply_message = pkt.unreach()
        reply_message.type = 3
        reply_message.payload = packet.payload.payload.payload
        reply_message.code = 0

        ipv4_datagram = ipv4()
        received_datagram = packet.payload
        ipv4_datagram.payload = reply_message
        ipv4_datagram.dstip = received_datagram.srcip
        ipv4_datagram.srcip = received_datagram.dstip
        ipv4_datagram.protocol = ipv4.ICMP_PROTOCOL
        ethernet_frame = ethernet()
        ethernet_frame.payload = ipv4_datagram
        ethernet_frame.src = packet.dst
        ethernet_frame.dst = packet.src
        ethernet_frame.type = ethernet.IP_TYPE

        self.resend_packet(ethernet_frame, packet_in.in_port)

    def construct_ARP(self ,destination , destination_network):
        request_message = arp()
        gateway = self.routing_table[destination_network]['gateway']
        request_message.hwsrc = EthAddr(self.ip_to_mac[gateway])
        request_message.hwdst = EthAddr ('AB:CD:EF:AB:CD:EF')
        request_message.protosrc = IPAddr(gateway)
        request_message.protodst = IPAddr(destination)
        request_message.opcode = arp.REQUEST

        ethernet_frame = ethernet()
        ethernet_frame.payload = request_message
        ethernet_frame.src = EthAddr(self.ip_to_mac[gateway])
        ethernet_frame.dst = EthAddr ('AB:CD:EF:AB:CD:EF')
        ethernet_frame.type = ethernet.ARP_TYPE
        return ethernet_frame

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        packet_in = event.ofp  # The actual ofp_packet_in message.
        packet_source =str(packet.src)
        packet_type = packet.type
        if packet_source not in self.mac_to_port:
            self.mac_to_port[packet_source] = packet_in.in_port
        if packet_type == ethernet.ARP_TYPE:
            self.ARP_packet(packet,packet_in)
        elif packet_type == ethernet.IP_TYPE:
            ipv4_datagram = packet.payload
            destination = ipv4_datagram.dstip
            reachable = False
            for network in self.routing_table:
                if destination.inNetwork(network):
                    destination_network = network
                    reachable =True
                    break

            if not reachable :
                log.debug("ICMP destination network unreachable")
                self.dest_unreachable(packet, packet_in)

            else:
                if ipv4_datagram.protocol == ipv4.ICMP_PROTOCOL:
                    self.ICMP_packet(packet, packet_in)
                else:
                    destination_str = str(destination)
                    out_port = self.routing_table[destination_network]['port']
                    if destination_str in self.ip_to_mac:
                        packet.src = EthAddr(self.ip_to_mac[self.routing_table[destination_network]['gateway']])
                        packet.dst = EthAddr(self.routing_table[destination_str])

                        self.resend_packet(packet,out_port)

                    else:
                        self.arp_set[destination_str] = [destination_network, ipv4_datagram]
                        self.resend_packet(self.construct_ARP(destination_str,destination_network),out_port)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Router(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

