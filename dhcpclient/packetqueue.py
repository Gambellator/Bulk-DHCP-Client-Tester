import socket
import struct
import os
import array
import Queue
import threading
import logging

from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU
from scapy.config import conf
from scapy.all import Ether, Dot1Q, IP, UDP, BOOTP, DHCP


class PacketQueue(object):
    '''
    PacketQueue class

    Listens to raw sockets once PacketQueue client's can join
    using thier particular DHCP XID, it must be unique. Both the receiver
    and the disperser run as seperate threads.
    
    '''
 
    def __init__(self, iface=None, queue_size=0):
        '''

        @iface=str
        @queue_size=int
        '''
        self.iface = conf.iface if iface is None else iface
        self.packet_queue = Queue.Queue(queue_size)
        self.pack_reciever_threadid = None
        self.pack_disperser_threadid = None
        self.stop_queuing = False
        self.register_queue = {}
 
        self.ins = socket.socket(socket.AF_PACKET,
                                 socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.iface, ETH_P_ALL))
        self.start()

    def start(self):
        '''
        Starts the packet_receiver and packet_disperser threads.
        '''
        self.stop_queuing = False
        ready = threading.Event()
        threading.Thread(target=self.packet_receiver, args=(ready,)).start()
        ready.wait()
        steady = threading.Event()
        threading.Thread(target=self.packet_disperser, args=(steady,)).start()
        steady.wait()

    def stop(self):
        self.stop_queuing = True
 
    def packet_receiver(self, ready, *args, **kargs):
        self.pack_reciever_threadid = threading.currentThread().ident
        ready.set()
        while True:

            if self.stop_queuing:
                break

            pkt, sa_ll = self.ins.recvfrom(MTU)

            if sa_ll[2] == socket.PACKET_OUTGOING:
                continue

            self.packet_queue.put((pkt, sa_ll))
        self.pack_reciever_threadid = None
 
    def packet_disperser(self, steady, *args, **kargs):
        self.pack_disperser_threadid = threading.currentThread().ident
        steady.set()
        while True:

            if self.stop_queuing:
                break
            
            try:
                pkt, sa_ll = self.packet_queue.get()
            except:
                break
            
            if sa_ll[3] in conf.l2types:
                cls = conf.l2types[sa_ll[3]]
            elif sa_ll[1] in conf.l3types:
                cls = conf.l3types[sa_ll[1]]
            else:
                cls = conf.default_l2
    
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)

            self.packet_dispersment(pkt)
        self.pack_disperser_threadid = None

    def packet_dispersment(self, pkt):
        if BOOTP in pkt:
            xid = pkt[BOOTP].xid
            if self.register_queue.has_key(xid):
                self.register_queue[xid].write(pkt)

    def register(self, register_key, register_class):
        xid = register_key
        if self.register_queue.has_key(xid):
            raise KeyError("xid in use")
        self.register_queue[xid] = register_class
        return self.register_queue[xid]


class DHCPListenSocket(object):

    def __init__(self, xid=None, packet_queue_class=None):
        self.rd, self.wr = os.pipe()
        self.queue = Queue.Queue()
        self.new_xid(xid=xid,packet_queue_class=packet_queue_class)

    def fileno(self):
        return self.rd

    def checkRecv(self):
        return len(self.queue) > 0

    def write(self, obj):
        self.send(obj)

    def send(self, obj):
        self.queue.put(obj)
        os.write(self.wr,"X")

    def new_xid(self, xid=None, packet_queue_class=None):
        try:
            packet_queue_class.register(xid, self)
        except:
            pass

    def recv(self, *args, **kargs):
        os.read(self.rd, 1)
        try:
            return self.queue.get(timeout=1)
        except Queue.Empty:
            return None

if __name__ == "__main__":
    ip_sniff = PacketQueue(iface='em4')
    ip_sniff.start()
    client = DHCPListenSocket(xid=100, packet_queue_class=ip_sniff)
    try:
        while True:
            client.recv().show()
    except:
        ip_sniff.stop()

