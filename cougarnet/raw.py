import bisect
import fcntl
import os
import select
import signal
import struct
import time

from mininet.log import debug, error

from scapy.all import IP, Ether, UDP

from .node import BaseNodeHandler, NoMatchingMethod, HostHandler
from .ether import ETH_P_IP, ETH_P_IPV6


class EndRun( Exception ):
    pass

class Event( object ):
    '''
    An Event to be scheduled.  An Event has an action, as well as positional
    and keyword arguments.
    '''

    def __init__( self, action, args, kwargs ):
        self.action = action
        self.args = args
        self.kwargs = kwargs

    def __repr__( self ):
        return str( self )

    def __str__( self ):
        return '<Event: %s>' % ( repr( self.action ) )

    def __lt__( self, other ):
        return id( self ) < id ( other )

    def run( self ):
        return self.action( *( self.args ), **( self.kwargs ) )

class RawPktFramework( object ):
    '''
    A framework for monitoring processes that send and receive raw network
    frames.  These are handled, along with general events, in an event loop.
    '''

    def __init__( self, net ):
        self.net = net
        self.wakeFhRead, self.wakeFhWrite = None, None
        self.epoll = select.epoll( )
        self.nodeIntfToRawPktPopen = {}
        self.rawPktInToIntf = {}
        self.events = []
        self._registerRawPacketHelpers( )
        self._registerWakePipe( )
        self._refTime = None

    @classmethod
    def _readFrame( cls, fd ):
        header_bytes = os.read( fd, 10 )
        if len( header_bytes ) == 0:
            return 0.0, b''
        ts_s, ts_us, frame_len = struct.unpack( '!IIH', header_bytes )
        if frame_len == 0:
            return 0.0, b''
        ts = ts_s * 1.0 + ( ts_us * 1.0 / 1e6 )
        return ts, os.read( fd, frame_len )

    def _set_wakeup_fd( self, fd ):
        def _send_sig( sig, stackFrame ):
            sig_bytes = struct.pack( '!B', sig )
            os.write( fd, sig_bytes )
        signal.signal( signal.SIGALRM, _send_sig )

    def _endRun( self ):
        raise EndRun( )

    def _registerWakePipe( self ):
        fdr, fdw = os.pipe( )
        self.wakeFhRead, self.wakeFhWrite = os.fdopen( fdr, 'rb' ), os.fdopen( fdw, 'wb' )
        fcntl.fcntl( self.wakeFhRead.fileno( ), fcntl.F_SETFL, os.O_NONBLOCK )
        fcntl.fcntl( self.wakeFhWrite.fileno( ), fcntl.F_SETFL, os.O_NONBLOCK )

        self._set_wakeup_fd( self.wakeFhWrite.fileno( ) )
        self.epoll.register( self.wakeFhRead.fileno( ), select.EPOLLIN )

    @classmethod
    def createUDPPacket( cls, payload, srcIP, dstIP, srcPort, dstPort ):
        if ':' in dstIP: # IPv6
            ipCls = IPv6
        else: # IPv4
            ipCls = IP
        udpHeader = UDP( sport=srcPort, dport=dstPort )
        ipHeader = ipCls( src=srcIP, dst=dstIP )
        return ipHeader / udpHeader / payload

    @classmethod
    def createFrame( cls, pkt, srcMAC, dstMAC ):
        if ':' in pkt.src: # IPv6
            ethType = ETH_P_IPV6
        else: # IPv4
            ethType = ETH_P_IP
        ethHeader = Ether( src=srcMAC, dst=dstMAC, type=ethType )
        return ethHeader / pkt

    def _registerRawPacketHelpers( self ):
        for node in self.net.hosts + self.net.switches:
            if not isinstance( node, BaseNodeHandler ):
                continue
            node.setHelper( self )
            for intf in node.ports:
                popen = node.startRawPktHelper( intf )
                if node not in self.nodeIntfToRawPktPopen:
                    self.nodeIntfToRawPktPopen[ node ] = {}
                self.nodeIntfToRawPktPopen[ node ][ intf ] = popen
                self.rawPktInToIntf[ popen.stdout.fileno( ) ] = intf
                self.epoll.register( popen.stdout.fileno( ), select.EPOLLIN )

            #TODO move this to node code
            node.clearForwardingTable( )

    def _handleWakeEvent( self ):
        while True:
            try:
                b = self.wakeFhRead.read( 1024 )
            except IOError:
                break
            if not b:
                break

    def _consumeEpollEvents( self ):
        events = self.epoll.poll( 0 )
        for fd, event in events:
            if fd == self.wakeFhRead.fileno( ):
                continue
            self._readFrame( fd )

    def _handleEpollEvents( self ):
        try:
            events = self.epoll.poll( )
        except IOError:
            # interrupted
            return
        for fd, event in events:
            if fd == self.wakeFhRead.fileno( ):
                self._handleWakeEvent( )
                continue
            intf = self.rawPktInToIntf[ fd ]
            ts, frame = self._readFrame( fd )
            ts = self._relativizeTime( ts )
            intf.node._handleFrame( ts, frame, intf )

    def _handleScheduledEvents( self ):
        handled = False
        while self.events:
            ts, event = self.events[ 0 ]
            if time.time( ) >= ts:
                debug( 'handling scheduled event: %s\n' % event.action )
                self.events.pop( 0 )
                event.run()
                handled = True
            else:
                break
        if handled and self.events:
            signal.setitimer( signal.ITIMER_REAL, max( ts - time.time( ), 0 ) )

    def resetEvents( self ):
        self.events = []
        self._refTime = None

    def _resetRefTime( self ):
        self._refTime = time.time( )

    def _relativizeTime( self, ts ):
        return ts - self._refTime

    def time( self ):
        return self._relativizeTime( time.time( ) )

    def _relativizeEventTimes( self ):
        newEvents = []
        now = time.time( )
        for ts, event in self.events:
            ts = now + ts
            newEvents.append( ( ts, event ) )
        self.events = newEvents
        if self.events:
            ts = self.events[0][0]
            signal.setitimer( signal.ITIMER_REAL, max( ts - time.time( ), 0 ) )

    def scheduleEvent( self, seconds, action, args=None, kwargs=None ):
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
            raise ValueError( 'Relative time cannot be negative: %d' % seconds )
        if args is None:
            args = ()
        if kwargs is None:
            kwargs = {}
        if self._refTime is None:
            ts = seconds
        else:
            ts = time.time( ) + seconds
        return self.scheduleEventAbs( ts, action, args, kwargs, force=True )

    def scheduleEventAbs( self, ts, action, args, kwargs, force=False ):
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

        if ts < time.time( ) and not force:
            raise ValueError( 'Event is scheduled in the past: %f' % ts )

        event = Event( action, args, kwargs )
        eventTuple = ( ts, event )
        i = bisect.bisect( self.events, eventTuple )
        self.events.insert( i, eventTuple )
        if i == 0:
            signal.setitimer( signal.ITIMER_REAL, max( ts - time.time( ), 0 ) )
        return event

    def cancelEvent( self, event ):
        '''
        Remove a given event from the queue of scheduled events.

        event: the Event instance that is to be removed/canceled.
        '''

        found = False
        for i, ( ts, ev ) in enumerate( self.events ):
            if ev == event:
                found = True
                break
        if found:
            self.events.remove( ( ts, event ) )
            if i == 0 and self.events:
                ts = self.events[0][0]
                signal.setitimer( signal.ITIMER_REAL, max( ts - time.time( ), 0 ) )

    def run( self, maxSeconds=None, minSeconds=2.0 ):
        '''
        Carry out scheduled events and also handle epoll events, e.g., from raw
        packet processes.  Terminate when either of the conditions are true:

            1. maxSeconds is None, minSeconds seconds have passed, and there
                are no more events scheduled.
            2. maxSeconds is not None, and maxSeconds seconds have passed.

        maxSeconds: the maximum number of seconds that the scenario should run.
        minSeconds: the miniumum number of seconds that the scenario should run.
        '''

        self._consumeEpollEvents( )
        self._relativizeEventTimes( )
        self._resetRefTime( )
        if maxSeconds is not None:
            self.scheduleEvent( maxSeconds, self._endRun )
        while True:
            if not self.events and self.time() > minSeconds:
                break
            try:
                self._handleScheduledEvents( )
                self._handleEpollEvents( )
            except EndRun as e:
                break
