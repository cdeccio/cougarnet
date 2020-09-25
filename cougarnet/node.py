import struct
import subprocess

from mininet.node import Node
from mininet.log import debug, warn, error
from mininet.util import moveIntf

from scapy.all import Ether, UDP

from .ether import ETH_P_IP, ETH_P_IPV6
from .forward import ForwardingTable
from .mac import ETH_BROADCAST
from .ip import IPPROTO_TCP, IPPROTO_UDP, IP_BROADCAST, IPAddress


class NoMatchingMethod(Exception):
    pass

class BaseNodeHandler( Node ):
    PROTOHANDLERS = {
    }

    def __init__( self, name, inNamespace=True, **params ):
        super( BaseNodeHandler, self ).__init__( name, inNamespace, **params )

        self.helper = None
        self.protocolHandlers = None
        self._installDefaultHandlers( )

    def setHelper( self, helper ):
        self.helper = helper

    def _installDefaultHandlers( self ):
        self.protocolHandlers = {}
        for layer in self.PROTOHANDLERS:
            self.protocolHandlers[ layer ] = {}
            for proto in self.PROTOHANDLERS[ layer ]:
                try:
                    handler = getattr( self, self.PROTOHANDLERS[ layer ][ proto ] )
                except AttributeError:
                    raise NoMatchingMethod( 'No matching matching method for protocol "%s"' % \
                            ( self.PROTOHANDLERS[ layer ][ proto ] ) )
                self.protocolHandlers[ layer ][ proto ] = handler

    def installHandler( self, layer, proto, handler ):
        if layer not in self.protocolHandlers:
            self.protocolHandlers[ layer ] = {}
        self.protocolHandlers[ layer ][ proto ] = handler

    def _handleNext( self, layer, proto, ts, pkt, intf ):
        try:
            handler = self.protocolHandlers[ layer ][ proto ]
        except KeyError:
            # drop - nothing to do
            warn( '*** %s: No handler for protocol %s at layer %s: %s\n' % \
                    ( self.name, proto, layer, repr( pkt ) ) )
            return None
        return handler( ts, pkt, intf )

    def _handleFrame( self, ts, frame, intf ):
        raise NotImplemented

    def sendFrame( self, frame, intf ):
        popen = self.intfPopen[ intf ]
        frame = bytes( frame )
        frameLen = len( frame )
        frameLenBytes = struct.pack( '!H', frameLen )
        popen.stdin.write( frameLenBytes + frame )
        popen.stdin.flush ( )

class Layer3Handler( BaseNodeHandler, Node ):
    PROTOHANDLERS = {
            'ETH': {
                ETH_P_IP: '_handleIP',
                ETH_P_IPV6: '_handleIP',
            },
            'IP': {
                IPPROTO_UDP: '_handleUDP',
                IPPROTO_TCP: '_handleTCP',
            },
            'UDP': {
            },
            'TCP': {
            }
    }

    def __init__( self, *args, **kwargs ):
        super( Layer3Handler, self ).__init__( *args, **kwargs )
        self.forwardingTable = ForwardingTable( )

        self.intfPopen = {}

    def disableArp( self, intf ):
        # disable arp and router solicitations
        intf.ifconfig( '-arp' )
        self.cmd( 'sysctl', 'net.ipv6.conf.%s.router_solicitations=0' % intf.name )


    def addIntf( self, intf, port=None, moveIntfFn=moveIntf ):
        super( Layer3Handler, self ).addIntf( intf, port, moveIntfFn )

        self.disableArp( intf )

    def clearForwardingTable( self ):
        #TODO do this as we add interfaces
        #TODO make it IPv6-compatible by updating Interface.IP( ) method (e.g., by creating an IP4( ) method)
        allRoutesStr = self.cmd( 'ip', 'route' )
        for routeStr in allRoutesStr.splitlines( ):
            route = routeStr.split( )
            self.cmd( 'ip', 'route', 'del', *route )

    def startRawPktHelper( self, intf ):
        cmd = [ 'mnrawpkthelper', intf.name ]
        popen = self.popen( *cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None )
        self.intfPopen[ intf ] = popen

        # send empty ready bytes (empty frame)
        popen.stdin.write( b'\x00\x00' )
        popen.stdin.flush()

        # wait on and consume the ready bytes (empty frame)
        popen.stdout.read( 2 )

        return popen

    def installAppHandlerUDP( self, localPort, handler, localAddress=None ):

        if localAddress is None:
            localAddress = self.intf().IP()
        key = ( localAddress, localPort )
        self.installHandler( 'UDP', key, handler )
        self.allowPackets( 'udp', localAddress, localPort )

    def installListenerTCP( self, localPort, handler, localAddress=None ):
        if localAddress is None:
            localAddress = self.intf().IP()
        key = ( localAddress, localPort )
        self.installHandler( 'TCP', key, handler )
        self.allowPackets( 'tcp', localAddress, localPort )

    def installAppHandlerTCP( self, localAddress, localPort,
            remoteAddress, remotePort, handler ):

        key = ( localAddress, localPort, remoteAddress, remotePort )
        self.installHandler( 'TCP', key, handler )

    def allowPackets( self, proto, localAddress, localPort ):
        self.cmd( 'iptables', '-A', 'INPUT', '-p', proto,
                '--destination', localAddress, '--dport', str( localPort ),
                '-j', 'DROP' )


    def _handleFrame( self, ts, frame, intf ):
        frame = Ether( frame )
        if frame.dst.lower( ) not in (intf.mac.lower( ), ETH_BROADCAST):
            # drop
            debug( '*** %s: Not my packet: %s\n' % \
                    ( self.name, repr( frame ) ) )
            return None
        return self._handleNext( 'ETH', frame.type, ts, frame.payload, intf )

    def _handleIP( self, ts, pkt, intf ):
        ipv4Addrs = [ intf.ip for intf in self.ports if intf.ip is not None ]
        ipv6Addrs = [ intf.ip6 for intf in self.ports if intf.ip6 is not None ]
        ipv6LLAddrs = [ intf.ip6ll for intf in self.ports if intf.ip6ll is not None ]

        if pkt.dst in ipv4Addrs or \
                pkt.dst in ipv6Addrs or \
                pkt.dst == IP_BROADCAST:
            self._handleNext( 'IP', pkt.proto, ts, pkt, intf )

        else:
            self._handleNotMyPacket( ts, pkt, intf )

    def _handleUDP( self, ts, pkt, intf ):
        key = ( pkt.dst, pkt.dport )
        return self._handleNext( 'UDP', key, ts, pkt, intf )

    def _handleTCP( self, ts, pkt, intf ):
        key1 = ( pkt.dst, pkt.dport, pkt.src, pkt.sport )
        key2 = ( pkt.dst, pkt.dport )
        # handle existing connections
        if 'TCP' in self.protocolHandlers and \
                key1 in self.protocolHandlers['TCP']:
            return self._handleNext( 'TCP', key1, ts, pkt, intf )
        # handle new connections
        else:
            return self._handleNext( 'TCP', key2, ts, pkt, intf )

    def _handleNotMyPacket( self, ts, pkt, intf ):
        warning('%0000.3f Host %s: ERROR: received packet from %s not destined for me %s\n' % \
                (ts, self.name, pkt.src, pkt.dst))



    def sendPacket( self, pkt ):
        dst = IPAddress( pkt.dst )
        if dst not in self.Table:
            error('%0000.3f Host %s: ERROR:  entry not found for %s\n' % \
                    (self.helper.time( ), self.name, pkt.dst))
            return

        intf, nextHop = self.Table.getEntry( pkt.dst )

        srcMAC = intf.MAC()
        dstMAC = self.getMAC( pkt.dst )

        frame = Ether( src=srcMAC, dst=dstMAC ) / pkt
        self.sendFrame( frame, intf )

    def getMAC( self, dstIP ):
        return ETH_BROADCAST

    def printDatagramPayload( self, ts, pkt, intf ):

        rawPayload = bytes( pkt.getlayer( UDP ).payload ).decode( 'utf-8' )
        print( '*** (%0.3f) %s: received UDP datagram: %s' % \
                ( ts, self.name, rawPayload ) )

    def addForwardingEntry( self, prefix, intf, nextHopIP ):
        self.forwardingTable.addEntry( prefix, intf, nextHopIP )

class RouterHandler( Layer3Handler ):

    def _handleNotMyPacket( self, ts, pkt, intf ):
        pkt.ttl -= 1
        if pkt.ttl == 0:
            warning( '%0000.3f Host %s: WARNING: TTL expired for packet destined for %s\n' % \
                    ( self.helper.time( ), self.name, pkt.dst ) )
        else:
            self.sendPacket( )

class HostHandler( Layer3Handler ):
    pass
