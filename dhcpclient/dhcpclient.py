"""dhcp.py"""
import logging
import string
import time
import binascii

from random import randint, choice

from scapy.config import conf

#conf.use_pcap = True
conf.verb = 0

from scapy.arch import linux, pcapdnet
from scapy.arch.pcapdnet import * 

#conf.L3socket = linux.L2Socket

from scapy.all import Ether, Dot1Q, IP, UDP, BOOTP, DHCP
from scapy.automaton import *

import packetqueue
global PACKET_QUEUE
PACKET_QUEUE = None

logging.getLogger("scapy").setLevel(1)
logger = logging.getLogger(__name__)

class DHCPClient(Automaton):
    '''
    '''
    BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    BROADCAST_IP  = '255.255.255.255'
    DEFAULT_IP    = '0.0.0.0'
    BOOTCLIENT    = 68
    BOOTSERVER    = 67
    DEBUF_RENEW_TIME = 30

    def __setattr__(self, name, value):
        logger.debug("Value: %s updated to: %s", name, value)
        super(DHCPClient, self).__setattr__(name, value)

    @staticmethod
    def mac_decode(mac_address):
        ''' takes a mac address removes . or : turns it into hex'''
        new_mac = mac_address.replace(":", "").replace(".", "")
        logger.debug("Stripped mac_address, old: %s new: %s", mac_address, new_mac)
        return new_mac.decode('hex')
    
    @staticmethod
    def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(choice(chars) for _ in range(size))
    
    @staticmethod
    def random_int():
        return randint(0, 2**32-1)

    @staticmethod
    def pad_zero(data):
        if len(data) < 2:
            data = '0' + data
        return data

    @staticmethod
    def encode_string(string_data):
        temp = []
        for char in string_data:
            new_hex = '{:x}'.format(ord(char))
            temp.append(DHCPClient.pad_zero(new_hex))
        length = DHCPClient.pad_zero('{:x}'.format(len(temp)))
        return length + ''.join(temp)

    def start_server(self):
        self.runbg()

    def stop_server(self):
        self.stop_state = True
        PACKET_QUEUE.stop()

    def server_status(self):
        return self.server_state

    def _server_update_state(self, server_state):
        self._state_update_parent(server_state)
        self.server_state = server_state

    def _state_update_parent(self, server_state):
        ''' Override with parent class method to update state'''
        pass

    def parse_args(self, interface, mac_address, hostname=None, broadcast=False, 
                                                 early_renew=0, early_rebind=0, 
                                                 no_renew=False, quick_start=False, dhcp_options=[],
                                                 vlan_tags=[], option82=None, dsl_sub_options=[], debug=100, **kargs):
        self.send_socket_kargs = {}
        Automaton.parse_args(self, **kargs)
        self.debug_level = 2
        #self.socket_kargs["ll"] = conf.L2socket
        self.interface       = interface
        conf.iface = self.interface
        if not PACKET_QUEUE:
            PACKET_QUEUE = packetqueue.PacketQueue(iface=conf.iface)
            global PACKET_QUEUE
        self.send_sock_class = conf.L2socket
        self.recv_sock_class = packetqueue.DHCPListenSocket
        #self.send_sock_class = pcapdnet.L2pcapSocket
        #self.recv_sock_class = pcapdnet.L2pcapListenSocket     
        self.send_socket_kargs['iface'] = self.interface
        self.mac_address     = mac_address
        self.hostname        = hostname
        self.broadcast       = broadcast
        self.early_renew     = early_renew
        self.early_rebind    = early_rebind
        self.no_renew        = no_renew
        self.quick_start     = quick_start
        self.dhcp_options    = dhcp_options
        self.vlan_tags       = vlan_tags
        self.option82        = option82
        self.dsl_sub_options = dsl_sub_options
        if not self.hostname: self.hostname = DHCPClient.id_generator()
        self.logger = logging.getLogger(self.hostname)

        self.xid             = 0
        self.flags           = 0
        self.t1              = 0
        self.t2              = 0
        self.siaddr          = '0.0.0.0'
        self.yiaddr          = '0.0.0.0'
        self.ciaddr          = '0.0.0.0'
        self.renew_attempts  = 0
        self.rebind_attempts = 0
        self.stop_state      = False
        self.server_state    = 'Stopped'

        if self.broadcast: self.flags = 32768
        self.raw_mac = DHCPClient.mac_decode(self.mac_address)

        self.logger.debug("Timeout for states are: %s", self.timeout)

    def my_send(self, pkt):
        self.send_sock.send(pkt)

    def master_filter(self, pkt):
        ''' '''
        return ( Ether in pkt and pkt[Ether].src != self.mac_address and (BOOTP in pkt and pkt[BOOTP].xid == self.xid) )

    def get_dot1q(self, vlan):
        return Dot1Q(vlan=vlan)

    def get_option82(self):
        send = False
        if self.option82:
            hex_subscriber_id = binascii.unhexlify('01' + DHCPClient.encode_string(self.option82))
            hex_remote_id = binascii.unhexlify('02' + DHCPClient.encode_string('BRASTEST'))
            send = True
        else:
            hex_subscriber_id = ''
            hex_remote_id = ''
        if len(self.dsl_sub_options) == 2:
            sup_option_header = binascii.unhexlify('0911' + '{0:08X}'.format(3561) + '0C')
            actual_up = binascii.unhexlify('8104' + '{0:08X}'.format(self.dsl_sub_options[0]))
            actual_down = binascii.unhexlify('8204' + '{0:08X}'.format(self.dsl_sub_options[1]))
            send = True
        else:
            sup_option_header = ''
            actual_up = ''
            actual_down = ''
        if send:
            return [('relay_agent_Information', hex_subscriber_id + hex_remote_id + sup_option_header + actual_up + actual_down)]
        return []

    def dhcp_add_options(self, header_options):
        self.logger.debug("dhcp options ")
        try:
            full_options  = header_options + self.dhcp_options + self.get_option82() + ['end']
        except:
            self.logger.exception("dhcp_options what!")
        self.logger.debug("dhcp options %s", full_options)
        return DHCP(options=full_options)

    def get_l2_transport(self, src_mac, dst_mac):
        ethernet = Ether(src=src_mac, dst=dst_mac)
        for vlan in self.vlan_tags:
            ethernet = ethernet / self.get_dot1q(vlan)
        return ethernet  

    def get_transport(self, src_mac, dst_mac, src_ip, dst_ip):
        ethernet = self.get_l2_transport(src_mac, dst_mac)
        ip_header = IP(src=src_ip, dst=dst_ip)
        udp_header = UDP(sport=self.BOOTCLIENT, dport=self.BOOTSERVER)
        return ethernet/ip_header/udp_header
    
    # State machine.
    #INIT - Init
    @ATMT.state(initial=1)
    def Init(self):
        ''' '''
        if self.stop_state: raise self.unbound_end()
        self._server_update_state("Unbound")
        self.logger.info("DHCP Client started for MAC %s", self.mac_address)
        l2_transport = self.get_transport(self.mac_address,
                                          self.BROADCAST_MAC,
                                          self.DEFAULT_IP,
                                          self.BROADCAST_IP)
        self.xid = DHCPClient.random_int()
        self.logger.info("XID set to: %s", self.xid)
        self.listen_sock = packetqueue.DHCPListenSocket(xid=self.xid, packet_queue_class=PACKET_QUEUE)
        
        if self.quick_start:
            logging.debug("Quick startup enabled, skipping random desync")
        else:
            desync_time = randint(1,30)
            logging.debug("Waiting for desync time to expire in %ss", desync_time)
            time.sleep(desync_time)            
            logging.debug("desync time expired, Sending Discover")

        bootp_header = BOOTP(flags=self.flags,chaddr=self.raw_mac,xid=self.xid)
        dhcp_header  = self.dhcp_add_options([('message-type', 'discover')])

        packet = l2_transport/bootp_header/dhcp_header
        self.logger.info("Sending Discover: %s", packet.sprintf('%Ether.src% > %Ether.dst% %Dot1Q.vlan% %IP.src% > %IP.dst% %BOOTP.xid%'))
        self.logger.debug("Sending Discover: %s", packet.show(dump=True))
        self.send(packet)

        raise self.Selecting()

    @ATMT.state()
    def Rebooting(self):
        self.siaddr = '0.0.0.0'
        self.yiaddr = '0.0.0.0'
        self.ciaddr = '0.0.0.0'
        raise self.Init()

    #SELECTING   - Selecting
    @ATMT.state()
    def Selecting(self):
        self.logger.info("Moved to state Selecting")

    @ATMT.timeout(Selecting, 15)
    def Selecting_timeout(self):
        self.logger.info("No repsonse back in 15 seconds heading back to Init state")
        raise self.Init()

    @ATMT.state()
    def Requesting(self):
        self.logger.info("Moved to state Requesting")
        l2_transport = self.get_transport(self.mac_address,
                                          self.BROADCAST_MAC,
                                          self.DEFAULT_IP,
                                          self.BROADCAST_IP)

        bootp_header = BOOTP(flags=self.flags,chaddr=self.raw_mac,xid=self.xid)
        dhcp_header  = DHCP(options=[("message-type","request"),
                                      ("server_id",self.siaddr),
                                      ("requested_addr",self.yiaddr),
                                      ("hostname",self.hostname),
                                      ("param_req_list","pad"),
                                      "end"])

        for option in self.dhcp_options:
            dhcp_header.options.append(option)

        packet = l2_transport/bootp_header/dhcp_header
        self.logger.info("Requesting: %s", packet.sprintf('%Ether.src% > %Ether.dst% VLAN:%Dot1Q.vlan% %IP.src% > %IP.dst% BOOTPXID:%BOOTP.xid%'))
        self.logger.debug("Requesting: %s", packet.show(dump=True))
        self.send(packet)

    @ATMT.state()
    def Bound(self):
        self._server_update_state("Bound")
        self.logger.info("Moved to state Bound with ip: %s", self.ciaddr)
        time_now = time.time()
        while time_now < self.lease_expire_time:
            if self.stop_state: raise self.bound_end()
            if not self.broadcast or not self.no_renew:
                if self.early_renew > 0 and self.early_renew < self.t1:
                    if time_now > self.early_renew_expire_time:
                        raise self.Renewing()
                if time_now > self.t1_expire_time:
                    raise self.Renewing()
            if time_now > self.t2_expire_time:
                raise self.Rebinding()
            elif (self.early_rebind > 0 and self.early_rebind < self.t2) and time_now > self.early_rebind_expire_time:
                raise self.Rebinding()
            time.sleep(1)
            time_now = time.time()
        raise self.Rebooting()

    @ATMT.state()
    def Renewing(self):
        self.logger.info("Moved to state Renewing")
        back_off_time = randint(1, self.DEBUF_RENEW_TIME) * self.renew_attempts
        self.logger.info("Backing off %ss", back_off_time)
        time.sleep(back_off_time)
        l2_transport = self.get_transport(self.mac_address,
                                          self.server_mac,
                                          self.yiaddr,
                                          self.siaddr)

        bootp_header = BOOTP(flags=self.flags,ciaddr=self.yiaddr,chaddr=self.raw_mac,xid=self.xid)
        dhcp_header  = DHCP(options=[("message-type","request"),
                                      ("hostname",self.hostname),
                                      "end"])

        packet = l2_transport/bootp_header/dhcp_header
        self.logger.info("Renewing: %s", packet.sprintf('%Ether.src% > %Ether.dst% VLAN:%Dot1Q.vlan% %IP.src% > %IP.dst% BOOTPXID:%BOOTP.xid%'))
        self.logger.debug("Renewing: %s", packet.show(dump=True))
        self.send(packet)
        self.renew_attempts += 1

    @ATMT.state()
    def Rebinding(self):
        self.logger.info("Moved to state Rebinding")
        back_off_time = randint(1, self.DEBUF_RENEW_TIME) * self.rebind_attempts
        self.logger.debug("Backing off %ss", back_off_time)
        time.sleep(back_off_time)
        l2_transport = self.get_transport(self.mac_address,
                                          self.BROADCAST_MAC,
                                          self.yiaddr,
                                          self.BROADCAST_IP)

        bootp_header = BOOTP(flags=self.flags,ciaddr=self.yiaddr,chaddr=self.raw_mac,xid=self.xid)
        dhcp_header  = DHCP(options=[("message-type","request"),
                                      ("hostname",self.hostname),
                                      "end"])

        packet = l2_transport/bootp_header/dhcp_header

        self.logger.info("Rebinding: %s", packet.sprintf('%Ether.src% > %Ether.dst% VLAN:%Dot1Q.vlan% %IP.src% > %IP.dst% BOOTPXID:%BOOTP.xid%'))
        self.logger.debug("Rebinding: %s", packet.show(dump=True))
        self.send(packet)
        self.rebind_attempts += 1

    @ATMT.timeout(Requesting, 30)
    def Requesting_timeout(self):
        self.logger.info("No repsonse back in 10 seconds heading back to Init state")
        raise self.Init()

    @ATMT.timeout(Renewing, 5)
    def waiting_renewing_response_timeout(self):
        self.logger.info("No repsonse back in 5 seconds heading back to Bound state")
        raise self.Bound()

    @ATMT.timeout(Rebinding, 5)
    def waiting_rebinding_response_timeout(self):
        self.logger.info("No repsonse back in 5 seconds heading back to Bound state")
        raise self.Bound()

    # State conditions and actions.
    @ATMT.receive_condition(Selecting)
    def received_offer(self, pkt):
        self.last_pkt = pkt
        self.logger.debug("Selecting condition")
        raise self.Requesting()

    @ATMT.receive_condition(Requesting)
    def recieved_packet_request(self, pkt):
        self.last_pkt = pkt
        raise self.Bound()

    @ATMT.receive_condition(Bound)
    def recieved_packet_bound(self, pkt):
        self.last_pkt = pkt
        raise self.Bound()

    @ATMT.receive_condition(Renewing)
    def recieved_packet_renewing(self, pkt):
        self.last_pkt = pkt
        raise self.Bound()

    @ATMT.receive_condition(Rebinding)
    def recieved_packet_rebinding(self, pkt):
        self.last_pkt = pkt
        raise self.Bound()

    @ATMT.action(received_offer)
    @ATMT.action(recieved_packet_request)
    @ATMT.action(recieved_packet_bound)
    @ATMT.action(recieved_packet_renewing)
    @ATMT.action(recieved_packet_rebinding)
    def recieved_packet(self):
        pkt = self.last_pkt
        if (UDP in pkt and BOOTP in pkt):
            self.logger.info("recieved_packet: %s", pkt.sprintf('%Ether.src% > %Ether.dst% VLAN:%Dot1Q.vlan% %IP.src% > %IP.dst% BOOTPXID:%BOOTP.xid%'))
            self.logger.debug("recieved_packet: %s", pkt.show(dump=True))
            if pkt[BOOTP].xid != self.xid:
                self.logger.warning("XID does not match! going to Init state, packet=%s, us=%s", pkt[BOOTP].xid, self.xid)

            elif ("message-type", 2) in pkt[DHCP].options: # OFFER
                self.siaddr = pkt[BOOTP].siaddr
                self.yiaddr = pkt[BOOTP].yiaddr
                self.server_mac = pkt[Ether].src
                for opt in pkt[DHCP].options:
                    if opt[0] == 'server_id':
                        self.siaddr = opt[1]
                raise self.Requesting()
            elif ("message-type", 5) in pkt[DHCP].options: # ACK
                time_now = time.time()
                self.ciaddr = self.yiaddr
                for opt in pkt[DHCP].options:
                    if opt[0] == 'renewal_time':
                        self.t1 = int(opt[1])
                    elif opt[0] == 'rebinding_time':
                        self.t2 = int(opt[1])
                    elif opt[0] == 'lease_time':
                        self.lease_time = int(opt[1])
                self.t1_expire_time = time_now + self.t1
                self.early_renew_expire_time = time_now + self.early_renew
                self.t2_expire_time = time_now + self.t2
                self.lease_expire_time = time_now + self.lease_time
                self.early_rebind_expire_time = time_now + self.early_rebind
                self.rebind_attempts = 0
                self.renew_attempts = 0
                raise self.Bound()
            elif ("message-type", 6) in pkt[DHCP].options: # NACK
                self.logger.info("Got NACK Rebooting")
                self._update_state("Unbound")
                raise self.Rebooting()
        self.logger.error("Packet was fucked")

    @ATMT.state()
    def bound_end(self):
        self.logger.debug("Moved to state Bounded Ending")
        l2_transport = self.get_transport(self.mac_address,
                                          self.server_mac,
                                          self.yiaddr,
                                          self.siaddr)

        bootp_header = BOOTP(flags=self.flags,ciaddr=self.yiaddr,chaddr=self.raw_mac,xid=self.xid)
        dhcp_header  = DHCP(options=[("message-type","release"),
                                      ("hostname",self.hostname),
                                      "end"])

        packet = l2_transport/bootp_header/dhcp_header
        self.logger.info("Bound Ending: %s", packet.sprintf('%Ether.src% > %Ether.dst% VLAN:%Dot1Q.vlan% %IP.src% > %IP.dst% BOOTPXID:%BOOTP.xid%'))
        self.logger.debug("Bound End: %s", packet.show(dump=True))
        self.send(packet)
        raise self.END()
    
    @ATMT.state()
    def unbound_end(self):
        raise self.END()

    @ATMT.state(final=1)
    def END(self):
        self._server_update_state("Stopped")
        self.logger.info("Client stopped")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    a = DHCPClient(sys.argv[1], sys.argv[2], quick_start=True, vlan_tags=[2001], option82='AVC999904444404')
    try:
        a.start_server()
        while True:
            pass
    except KeyboardInterrupt:
        a.stop_server()
        while True:
            if a.server_status() == "Stopped":
                sys.exit()

