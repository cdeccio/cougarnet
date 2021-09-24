import bisect
import ctypes
import errno
import fcntl
import os
import select
import signal
import socket
import struct
import time

# From: /usr/include/asm-generic/socket.h:
SO_BINDTODEVICE = 25

# From: /usr/include/linux/if_ether.h
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806

# From bits/socket.h
SOL_PACKET = 263

# From asm/socket.h
SO_ATTACH_FILTER = 26
ETH_P_8021Q = 0x8100
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4

class tpacket_auxdata(ctypes.Structure):
    _fields_ = [
        ("tp_status", ctypes.c_uint),
        ("tp_len", ctypes.c_uint),
        ("tp_snaplen", ctypes.c_uint),
        ("tp_mac", ctypes.c_ushort),
        ("tp_net", ctypes.c_ushort),
        ("tp_vlan_tci", ctypes.c_ushort),
        ("tp_padding", ctypes.c_ushort),
    ]

class EndRun(Exception):
    pass

class Event(object):
    '''
    An Event to be scheduled.  An Event has an action, as well as positional
    and keyword arguments.
    '''

    def __init__(self, action, args, kwargs):
        self.action = action
        self.args = args
        self.kwargs = kwargs

    def __repr__(self):
        return str(self)

    def __str__(self):
        return '<Event: %s>' % (repr(self.action))

    def __lt__(self, other):
        return id(self) < id (other)

    def run(self):
        return self.action(*(self.args), **(self.kwargs))

class NetworkEventLoop(object):
    '''
    An event loop for monitoring network interfaces for incoming frames, and
    other related events.
    '''

    def __init__(self, handle_frame):
        self._handle_frame = handle_frame
        self.wake_fh_read, self.wake_fh_write = None, None
        self.epoll = select.epoll()
        self.sock_to_int = {}
        self.fd_to_sock = {}
        self.events = []
        self._setup_receive_sockets()
        self._register_wake_pipe()
        self._ref_time = None

    def _set_wakeup_fd(self, fd):
        def _send_sig(sig, stack_frame):
            sig_bytes = struct.pack('!B', sig)
            os.write(fd, sig_bytes)
        signal.signal(signal.SIGALRM, _send_sig)

    def _end_run(self):
        raise EndRun()

    def _register_wake_pipe(self):
        fdr, fdw = os.pipe()
        self.wake_fh_read, self.wake_fh_write = os.fdopen(fdr, 'rb'), os.fdopen(fdw, 'wb')
        fcntl.fcntl(self.wake_fh_read.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(self.wake_fh_write.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

        self._set_wakeup_fd(self.wake_fh_write.fileno())
        self.epoll.register(self.wake_fh_read.fileno(), select.EPOLLIN)

    def _setup_receive_sockets(self):
        ints = os.listdir('/sys/class/net/')
        for intf in ints:

            if intf.startswith('lo'):
                continue

            # For receiving...
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((intf, 0))
            sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)

            sock.setblocking(False)
            self.epoll.register(sock.fileno(), select.EPOLLIN)
            self.sock_to_int[sock.fileno()] = intf
            self.fd_to_sock[sock.fileno()] = sock

    def _handle_wake_event(self):
        while True:
            try:
                b = self.wake_fh_read.read(1024)
            except IOError:
                break
            if not b:
                break

    def _consume_epoll_events(self):
        events = self.epoll.poll(0)
        for fd, event in events:
            if fd == self.wake_fh_read.fileno():
                continue
            sock = self.fd_to_sock[fd]
            sock.recvfrom(4096)

    def _recv_raw(self, sock, bufsize):
        """Internal function to receive a Packet,
        and process ancillary data.

        From: https://github.com/secdev/scapy/pull/2091/files
        """

        flags_len = socket.CMSG_LEN(4096)
        pkt, ancdata, flags, sa_ll = sock.recvmsg(bufsize, flags_len)

        if not pkt:
            return pkt, sa_ll

        for cmsg_lvl, cmsg_type, cmsg_data in ancdata:
            # Check available ancillary data
            if (cmsg_lvl == SOL_PACKET and cmsg_type == PACKET_AUXDATA):
                # Parse AUXDATA
                auxdata = tpacket_auxdata.from_buffer_copy(cmsg_data)
                if auxdata.tp_vlan_tci != 0 or \
                        auxdata.tp_status & TP_STATUS_VLAN_VALID:
                    # Insert VLAN tag
                    tag = struct.pack(
                        "!HH",
                        ETH_P_8021Q,
                        auxdata.tp_vlan_tci
                    )
                    pkt = pkt[:12] + tag + pkt[12:]
        return pkt, sa_ll

    def _handle_epoll_events(self):
        try:
            events = self.epoll.poll()
        except IOError:
            # interrupted
            return
        for fd, event in events:
            if fd == self.wake_fh_read.fileno():
                self._handle_wake_event()
                continue
            intf = self.sock_to_int[fd]
            sock = self.fd_to_sock[fd]
            frame, info = self._recv_raw(sock, 4096)
            (ifname, proto, pkttype, hatype, addr) = info
            if pkttype == socket.PACKET_OUTGOING:
                continue
            self._handle_frame(frame, intf)

    def _handle_scheduled_events(self):
        handled = False
        while self.events:
            ts, event = self.events[0]
            if time.time() >= ts:
                self.events.pop(0)
                event.run()
                handled = True
            else:
                break
        if handled and self.events:
            signal.setitimer(signal.ITIMER_REAL, max(ts - time.time(), 0))

    def reset_events(self):
        self.events = []
        self._ref_time = None

    def _reset_ref_time(self):
        self._ref_time = time.time()

    def _relativize_time(self, ts):
        return ts - self._ref_time

    def time(self):
        return self._relativize_time(time.time())

    def _relativize_event_times(self):
        new_events = []
        now = time.time()
        for ts, event in self.events:
            ts = now + ts
            new_events.append((ts, event))
        self.events = new_events
        if self.events:
            ts = self.events[0][0]
            signal.setitimer(signal.ITIMER_REAL, max(ts - time.time(), 0))

    def schedule_event(self, seconds, action, args=None, kwargs=None):
        '''
        Schedule an action to happen in the future, based on a time relative to
        the current time.  Return the Event() instance corresponding to the
        scheduled action.

        seconds: a float, the amount of time in the future that the action
                should happen.
        action: the function or method that should be called.
        args: a tuple of one or more arguments that should be passed to the
                function or method when it is called.
        kwargs: a dictionary of one or more keyword argument pairs that should
                be passed to the function or method when it is called.
        '''

        if seconds < 0:
            raise ValueError('Relative time cannot be negative: %d' % seconds)
        if args is None:
            args = ()
        if kwargs is None:
            kwargs = {}
        if self._ref_time is None:
            ts = seconds
        else:
            ts = time.time() + seconds
        return self.schedule_event_abs(ts, action, args, kwargs, force=True)

    def schedule_event_abs(self, ts, action, args, kwargs, force=False):
        '''
        Schedule an action to happen at a specific time in the future.  Return
        the Event() instance corresponding to the scheduled action.

        seconds: a float representing the time in the future that the action
                should happen.
        action: the function or method that should be called.
        args: a tuple of one or more arguments that should be passed to the
                function or method when it is called.
        kwargs: a dictionary of one or more keyword argument pairs that should
                be passed to the function or method when it is called.
        '''

        if ts < time.time() and not force:
            raise ValueError('Event is scheduled in the past: %f' % ts)

        event = Event(action, args, kwargs)
        event_tuple = (ts, event)
        i = bisect.bisect(self.events, event_tuple)
        self.events.insert(i, event_tuple)
        if i == 0:
            signal.setitimer(signal.ITIMER_REAL, max(ts - time.time(), 0))
        return event

    def cancel_event(self, event):
        '''
        Remove a given event from the queue of scheduled events.

        event: the Event instance that is to be removed/canceled.
        '''

        found = False
        for i, (ts, ev) in enumerate(self.events):
            if ev == event:
                found = True
                break
        if found:
            self.events.remove((ts, event))
            if i == 0 and self.events:
                ts = self.events[0][0]
                signal.setitimer(signal.ITIMER_REAL, max(ts - time.time(), 0))

    def run(self):
        '''
        Carry out scheduled events and also handle epoll events, e.g., from raw
        packet processes.
        '''

        self._consume_epoll_events()
        self._relativize_event_times()
        self._reset_ref_time()
        while True:
            try:
                self._handle_scheduled_events()
                self._handle_epoll_events()
            except EndRun as e:
                break
            except OSError as e:
                if e.errno == errno.ENETDOWN:
                    # If network is down, just break out of the loop
                    break
                raise
