import os
import socket

#From /usr/include/linux/if_ether.h:
ETH_P_ALL = 0x0003

class BaseFrameHandler:
    def __init__(self):
        self.int_to_sock = {}
        self.comm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.comm_sock.connect(os.environ['COUGARNET_COMM_SOCK'])
        self.hostname = socket.gethostname()
        self._setup_send_sockets()

    def _setup_send_sockets(self):
        ints = os.listdir('/sys/class/net/')
        for intf in ints:
            if intf.startswith('lo'):
                continue

            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_ALL)
            sock.bind((intf, 0))
            self.int_to_sock[intf] = sock

    def send_frame(self, frame, intf):
        self.int_to_sock[intf].send(frame)

    def log(self, msg):
        self.comm_sock.send(f'{self.hostname},{msg}'.encode('utf-8'))
