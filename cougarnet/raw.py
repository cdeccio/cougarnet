import bisect
import fcntl
import os
import select
import signal
import struct
import time

from mininet.log import debug, error

from scapy.all import IP, Ether, UDP

from .node import BaseHandler, NoMatchingMethod, HostHandler
from .ether import ETH_P_IP, ETH_P_IPV6


class EndRun( Exception ):
    pass

class Event( object ):
    def __init__( self, action, args ):
        self.action = action
        self.args = args

    def __str__( self ):
        return '<Event: %s>' % ( repr( action ) )

class RawPktFramework( object ):

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
            if not isinstance( node, BaseHandler ):
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
            node.clearRoutingTable( )

    def _handleWakeEvent( self ):
        while True:
            try:
                b = self.wakeFhRead.read( 1024 )
            except IOError:
                break
            if not b:
                break

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
                event.action( *( event.args ) )
                handled = True
            else:
                break
        if handled and self.events:
            signal.setitimer( signal.ITIMER_REAL, max( ts - time.time( ), 0 ) )

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

    def scheduleEvent( self, seconds, action, args=None ):
        if seconds < 0:
            raise ValueError( 'Relative time cannot be negative: %d' % seconds )
        if args is None:
            args = ( )
        if self._refTime is None:
            ts = seconds
        else:
            ts = time.time( ) + seconds
        return self.scheduleEventAbs( ts, action, args, force=True )

    def scheduleEventAbs( self, ts, action, args, force=False ):
        if ts < time.time( ) and not force:
            raise ValueError( 'Event is scheduled in the past: %f' % ts )
        event = ( ts, Event( action, args ) )
        i = bisect.bisect( self.events, event )
        self.events.insert( i, event )
        if i == 0:
            signal.setitimer( signal.ITIMER_REAL, max( ts - time.time( ), 0 ) )
        return event

    def cancelEvent( self, event ):
        found = False
        for ts, ev in self.events:
            if event == event:
                found = True
                break
        if found:
            self.events.remove( ( ts, event ) )

    def run( self, maxSeconds ):
        self._relativizeEventTimes( )
        self._resetRefTime( )
        self.scheduleEvent( maxSeconds, self._endRun )
        while True:
            try:
                #print( [ '%00.3f' % self._relativizeTime( i[0] ) for i in self.events ])
                self._handleScheduledEvents( )
                self._handleEpollEvents( )
            except EndRun as e:
                break
