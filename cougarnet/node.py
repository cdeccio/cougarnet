import logging
import struct
import subprocess

from mininet.node import Node
from mininet.log import lg, debug, warn, error
from mininet.util import moveIntf

from scapy.all import Ether, UDP

from .ether import ETH_P_IP, ETH_P_IPV6
from .forward import ForwardingTable
from .mac import ETH_BROADCAST
from .ip import IPPROTO_TCP, IPPROTO_UDP, IP_BROADCAST, IPAddress


class NoMatchingMethod(Exception):
    pass

class BaseNodeHandler( Node ):
    '''
    Base Node Handler class.  Extends mininet.node.Node to include handling of
    raw packets, layer by layer.
    '''

    PROTOHANDLERS = {
    }

    def __init__( self, name, inNamespace=True, **params ):
        super( BaseNodeHandler, self ).__init__( name, inNamespace, **params )

        self.helper = None
        self.protocolHandlers = None
        self._installDefaultHandlers( )

    def setHelper( self, helper ):
        '''
        Set the raw packet helper that is used send raw frames on the wire.
        '''

        self.helper = helper

    def _installDefaultHandlers( self ):
        '''
        Install the protocol handlers that are defined by the class.
        '''

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
        '''
        Install a handler for a given layer and protocol.  This tells the node
        what method or function to call when a packet with certain
        characteristics (proto) is received at a given layer (layer).  For
        example, we would call the following:

            n.installHandler( 'ETH', ETH_P_IP, handleIP )

        to have node n call handleIP when it receives an Ethernet frame whose
        payload is an IP packet.  Similarly, the following:

            n.installHandler( 'IP', IPPROTO_UDP, handleUDP )

        would be used to have n call handleUDP when an IP packet is encountered
        with a UDP payload.  Note that the type and value of proto can be
        protocol-specific.  For example, it might be an integer or a tuple or
        something else.


        layer: a string representing which network layer is *currently* being
                handled, i.e., where we're coming from.  For example, 'ETH',
                'IP', 'TCP', 'UDP'
        proto: a value identifying the protocol that will be handled *next*,
                i.e., where we're going to.  For example, ETH_P_IP (for IP from
                Ethernet), IPPROTO_UDP (for UDP from IP), the tuple
                ('192.0.2.1', 5599) for 192.0.2.1:5599 from UDP, etc.
        handler: the handler (function or method) that will be called.
        '''

        if layer not in self.protocolHandlers:
            self.protocolHandlers[ layer ] = {}
        self.protocolHandlers[ layer ][ proto ] = handler

    def _handleNext( self, layer, protoList, ts, pkt, intf ):
        '''
        Lookup and call the designated handler on a packet, for a given layer
        and protocol.  If there is no handler installed for the given layer and
        protocol, then log an error.

        layer: a string representing which network layer is *currently* being
                handled.  See installHandler().
        protoList: a list of values identifying the protocol that will be
                handled *next*.  See installHandler().
        ts: a float representing the timestamp (seconds and microseconds) at
                which the packet was received by the interface.
        pkt: the packet being handled.  Note that the packet includes a header
                and a payload.  Depending on the layer, the payload might
                itself have another header.  For example, if this is an IP
                packet, then pkt is an instance of scapy.all.IP (or
                scapy.all.IPv6, for IPv6), and pkt.payload returns the scapy.all.TCP or
                scapy.all.UDP instance corresponding to the TCP or UDP header
                and its segment/payload.  If this is a TCP packet, then pkt is
                an instance of scapy.all.TCP, and pkt.payload returns the
                scapy.all.Raw instance corresponding to the raw data
                representing the TCP segment.
        '''

        if layer in self.protocolHandlers:
            for proto in protoList:
                if proto in self.protocolHandlers[ layer ]:
                    handler = self.protocolHandlers[ layer ][ proto ]
                    return handler( ts, pkt, intf )

        # drop - nothing to do
        warn( '%.3f %s No handler for protocol %s at layer %s: %s\n' % \
                ( ts, self.name, protoList[0], layer, repr( pkt ) ) )
        return None

    def _handleFrame( self, ts, frame, intf ):
        raise NotImplemented

    def sendFrame( self, frame, intf ):
        '''
        Send the frame using the raw packet helper process corresponding to the
        interface.  The interface maps to the input pipe for this process using
        self.intfPopen[intf].  The size of the frame is calculated, and the
        size of the frame and frame itself are sent to the helper, to be placed
        on the wire.  This placement on the wire is done by the raw packet
        helper process.

        frame: an instance of scapy.all.Ether representing Ethernet frame to be
                sent.
        intf: An instance of mininet.link.Intf that represents the interface
                out which the Ethernet frame should be sent.
        '''

        popen = self.intfPopen[ intf ]
        frame = bytes( frame )
        frameLen = len( frame )
        frameLenBytes = struct.pack( '!H', frameLen )
        popen.stdin.write( frameLenBytes + frame )
        popen.stdin.flush ( )

class Layer3Handler( BaseNodeHandler, Node ):
    '''
    A Node Handler specific to Nodes that operate at Layer3, e.g., hosts and
    routers.
    '''

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

    def __init__( self, *args, disableArp=True, disableRS=True,
            useKernelForwardingTable=False, **kwargs ):
        super( Layer3Handler, self ).__init__( *args, **kwargs )

        self.forwardingTable = ForwardingTable( )
        self.intfPopen = {}

        self._disableArp = disableArp
        self._disableRS = disableRS
        self._useKernelForwardingTable = useKernelForwardingTable

        if self._useKernelForwardingTable:
            self.setRoute = self._setRouteKernel
        else:
            self.setRoute = self._setRoute

    def disableArp( self, intf ):
        '''
        Disable ARP (i.e., by the kernel) for the specified interface.

        intf: An instance of mininet.link.Intf that represents the interface
                for which ARP should be disabled.
        '''

        # disable ARP
        intf.ifconfig( '-arp' )

    def disableRS( self, intf ):
        '''
        Disable router solicitations for the specified interface.

        intf: An instance of mininet.link.Intf that represents the interface
                for which ARP should be disabled.
        '''

        # disable RS
        self.cmd( 'sysctl', 'net.ipv6.conf.%s.router_solicitations=0' % intf.name )


    def addIntf( self, intf, port=None, moveIntfFn=moveIntf ):
        '''
        Override mininet.node.Node.addIntf() such that the parent method is
        called and then ARP is disabled for the interface.
        '''

        super( Layer3Handler, self ).addIntf( intf, port, moveIntfFn )

        if self._disableArp:
            self.disableArp( intf )
        if self._disableRS:
            self.disableRS( intf )

    #TODO add this to mininet
    def setHostRoute( self, ip, intf, nextHop=None ):
        """Add route to host.
           ip: IP address as dotted decimal
           intf: string, interface name
           nextHop: IP address as dotted decimal"""
        if nextHop is None:
            cmd = ( 'route add -host', ip, 'dev', intf )
        else:
            cmd = ( 'route add -host', ip, 'gw', nextHop, 'dev', intf )
        return self.cmd( *cmd )

    def setNetRoute( self, prefix, intf, nextHop=None ):
        """Add route to host.
           prefix: IP address as dotted decimal
           intf: string, interface name
           nextHop: IP address as dotted decimal"""
        if nextHop is None:
            cmd = ( 'route add -net', prefix, 'dev', intf )
        else:
            cmd = ( 'route add -net', prefix, 'gw', nextHop, 'dev', intf )
        return self.cmd( *cmd )

    def getForwardingTable( self ):
        '''
        Retrieves all "via" (i.e., with next hop) routes from kernel's route
        table as a dictionary where the destination IP is mapped to tuple
        composed of intf and nextHop.
        '''

        #TODO make it IPv6-compatible by updating Interface.IP( ) method (e.g., by creating an IP4( ) method)
        allRoutesStr = self.cmd( 'ip', 'route' )
        routes = {}
        for routeStr in allRoutesStr.splitlines( ):
            route = routeStr.split( )
            if len( route ) > 1 and route[ 1 ] == 'via':
                ip, nextHop, intf = route[0], route[2], self.nameToIntf[ route[4] ]
                routes[ ip ] = ( intf, nextHop )
        return routes

    def _clearForwardingTable( self ):
        '''
        Clear all "via" (i.e., with next hop) entries from the kernel's
        forwarding table for the node.  This is useful for when we're using the
        kernel's forwarding table but want to maintain the non-local routes
        manually.
        '''

        #TODO do this as we add interfaces
        #TODO make it IPv6-compatible by updating Interface.IP( ) method (e.g., by creating an IP4( ) method)
        allRoutesStr = self.cmd( 'ip', 'route' )
        for routeStr in allRoutesStr.splitlines( ):
            route = routeStr.split( )
            if len( route ) > 1 and route[ 1 ] == 'via':
                self.cmd( 'ip', 'route', 'del', *route )

    def _clearForwardingTableAll( self ):
        '''
        Clear all entries from the kernel's forwarding table for the node.
        This allows this Layer-3 node to maintain its own forwarding table,
        rather than the kernel.
        '''

        #TODO do this as we add interfaces
        #TODO make it IPv6-compatible by updating Interface.IP( ) method (e.g., by creating an IP4( ) method)
        allRoutesStr = self.cmd( 'ip', 'route' )
        for routeStr in allRoutesStr.splitlines( ):
            route = routeStr.split( )
            self.cmd( 'ip', 'route', 'del', *route )

    def startRawPktHelper( self, intf ):
        '''
        Start a raw packet helper for a given interface, an process that does
        only the following:
            1) listens on stdin for frames to be sent on the interface, and
                sends them on that interface;
            2) listens for incoming frames on the interface and sends them to
                stdout.
        Map the interface to the process, so we know which process to
        communicate with when an incoming frame is detected on the interfaces.
        '''
        
        cmd = [ 'mnrawpkthelper' ]
        if lg.getEffectiveLevel() > logging.INFO:
            cmd.append( '-q' )
        cmd.append( intf.name )
        popen = self.popen( *cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None )
        self.intfPopen[ intf ] = popen

        # send empty ready bytes (empty frame)
        popen.stdin.write( b'\x00\x00' )
        popen.stdin.flush()

        # wait on and consume the ready bytes (empty frame)
        popen.stdout.read( 2 )

        return popen

    def installAppHandlerUDP( self, localPort, handler, localAddress=None ):
        '''
        Install a handler for a UDP application using a local port and local
        address (optional).  When a UDP packet with destination address and
        destination port match localPort and localAddress, handler will be
        called.

        localPort: an integer representing the local port.
        handler: the handler (function or method) that will be called.
        localAddress: an IP address (string) representing the local address.
                If not specified, this is inferred using the IP address with
                which the interface is configured.
        '''

        key = ( localAddress, localPort )
        self.installHandler( 'UDP', key, handler )
        self.allowPackets( 'udp', localAddress, localPort )

    def installListenerTCP( self, localPort, handler, localAddress=None ):
        '''
        Install a handler for new (unestablished) TCP communications using a
        local port and local address (optional).  When a TCP packet with
        destination address and destination port match localPort and
        localAddress--and that TCP packet does not match an existing,
        established connection--this handler will be called.

        localPort: an integer representing the local port.
        handler: the handler (function or method) that will be called.
        localAddress: an IP address (string) representing the local address.
                If not specified, this is inferred using the IP address with
                which the interface is configured.
        '''

        key = ( localAddress, localPort )
        self.installHandler( 'TCP', key, handler )
        self.allowPackets( 'tcp', localAddress, localPort )

    def installAppHandlerTCP( self, localAddress, localPort,
            remoteAddress, remotePort, handler ):
        '''
        Install a handler for an established TCP connection using a local
        address, local port, remote address, and remote port. When a TCP packet
        arrives with matching destination address, destination port, source
        address, and source port, the handler will be called.

        localPort: an integer representing the local port.
        localAddress: an IP address (string) representing the local address.
        remotePort: an integer representing the remote port.
        remoteAddress: an IP address (string) representing the remote address.
        handler: the handler (function or method) that will be called.
        '''

        key = ( localAddress, localPort, remoteAddress, remotePort )
        self.installHandler( 'TCP', key, handler )

    def allowPackets( self, proto, localAddress, localPort ):
        '''
        Create an iptables rule to drop packets arriving for given destination
        address and port.  This allows us to communicate at the sub-application
        layers without interference with the kernel.  Without this rule, the
        packet would be allowed by netfilter to reach the kernel, and the
        kernel would find no established listener and send a TCP RST (reset) to
        the sender.

        proto: a string representing the transport-layer protocol, either 'udp'
                or 'tcp'
        localPort: an integer representing the local port.
        localAddress: an IP address (string) representing the local address.
        '''

        self.cmd( 'iptables', '-A', 'INPUT', '-p', proto,
                '--destination', localAddress, '--dport', str( localPort ),
                '-j', 'DROP' )

    def enableForwarding( self ):
        '''Enable IP forwarding (IPv4).'''

        self.cmd( 'sysctl', 'net.ipv4.ip_forward=1' )

    def _handleFrame( self, ts, frame, intf ):
        '''
        Handle a frame received on the wire.  Check the destination MAC address
        on the frame.  Only keep it if it's our own MAC address or the
        broadcast MAC address.  If it's a keeper, call the handler for the
        next layer up.

        ts: a float representing the timestamp (seconds and microseconds) at
                which the packet was received by the interface.
        frame: the frame being handled.  Note that the packet includes a frame
                header and a payload. The frame is an instance of
                scapy.all.Ether, and frame.payload returns an instance of the
                the packet class for the next layer above Ethernet, typically
                scapy.all.IP or scapy.all.IPv6.
        intf: An instance of mininet.link.Intf that represents the interface
                on which the Ethernet frame was received.
        '''

        frame = Ether( frame )
        if frame.dst.lower( ) not in (intf.mac.lower( ), ETH_BROADCAST):
            # drop
            debug( '*** %s: Not my packet: %s\n' % \
                    ( self.name, repr( frame ) ) )
            return None
        return self._handleNext( 'ETH', ( frame.type, ), ts, frame.payload, intf )

    def _handleIP( self, ts, pkt, intf ):
        '''
        Handle an incoming IP packet.  Check the destination IP address
        of the packet.  Only keep it if it's our own IP (or IPv6) address or the
        broadcast IP address.  If it's a keeper, call the handler for the
        next layer up.  Otherwise, call self._handleNotMyPacket() on the packet.

        ts: a float representing the timestamp (seconds and microseconds) at
                which the packet was received by the interface.
        pkt: the packet being handled, an instance of scapy.all.IP or
                scapy.all.IPv6.  In either case, frame.payload returns an
                instance of scapy.all.TCP or scapy.all.UDP.  See _handleNext().
        intf: An instance of mininet.link.Intf that represents the interface
                on which the packet was received.
        '''

        ipv4Addrs = [ intf.ip for intf in self.ports if intf.ip is not None ]
        ipv6Addrs = [ intf.ip6 for intf in self.ports if intf.ip6 is not None ]
        ipv6LLAddrs = [ intf.ip6ll for intf in self.ports if intf.ip6ll is not None ]

        if pkt.dst in ipv4Addrs or \
                pkt.dst in ipv6Addrs or \
                pkt.dst == IP_BROADCAST:
            self._handleNext( 'IP', ( pkt.proto, ), ts, pkt, intf )

        else:
            self._handleNotMyPacket( ts, pkt, intf )

    def _handleUDP( self, ts, pkt, intf ):
        '''
        Handle an incoming UDP/IP packet.  Look up and call the handler
        corresponding to the destination IP address and destination UDP port.

        ts: a float representing the timestamp (seconds and microseconds) at
                which the packet was received by the interface.
        pkt: the packet being handled, an instance of scapy.all.IP or
                scapy.all.IPv6.  In either case, frame.payload returns an
                instance of scapy.all.UDP.  See _handleNext().
        intf: An instance of mininet.link.Intf that represents the interface
                on which the packet was received.
        '''

        protoList = [ ( pkt.dst, pkt.dport ),
                    ( None, pkt.dport ) ]
        return self._handleNext( 'UDP', protoList, ts, pkt, intf )

    def _handleTCP( self, ts, pkt, intf ):
        '''
        Handle an incoming TCP/IP packet.  Look up a handler, by looking up the
        following, in order:
            1) a handler matching the destination address, destination port, source address,
                and source port (i.e., an established connection)
            2) a handler matching the destination address and destination port
                (i.e., a new, unestablished connection)
        Call the first handler that is found.

        ts: a float representing the timestamp (seconds and microseconds) at
                which the packet was received by the interface.
        pkt: the packet being handled, an instance of scapy.all.IP or
                scapy.all.IPv6.  In either case, frame.payload returns an
                instance of scapy.all.TCP.  See _handleNext().
        intf: An instance of mininet.link.Intf that represents the interface
                on which the packet was received.
        '''

        protoList = [ ( pkt.dst, pkt.dport, pkt.src, pkt.sport ),
                    ( None, pkt.dport, pkt.src, pkt.sport ),
                    ( pkt.dst, pkt.dport ),
                    ( None, pkt.dport ) ]
        return self._handleNext( 'TCP', protoList, ts, pkt, intf )

    def _handleNotMyPacket( self, ts, pkt, intf ):
        '''
        Warn that a packet received was not destined for this node.

        ts: a float representing the timestamp (seconds and microseconds) at
                which the packet was received by the interface.
        pkt: the packet being handled, an instance of scapy.all.IP or
                scapy.all.IPv6.
        intf: An instance of mininet.link.Intf that represents the interface
                on which the packet was received.
        '''

        warning('%0000.3f Host %s: ERROR: received packet from %s not destined for me %s\n' % \
                (ts, self.name, pkt.src, pkt.dst))

    def sendPacket( self, pkt, intf=None ):
        '''
        Send an IP (or IPv6) packet.  If intf is not specified, look up the
        interface from which the packet should be sent using this node's
        forwarding table, .  If an entry exists, create an Ethernet frame for
        the packet, and send it out the outgoing interface.

        pkt: the packet being handled, an instance of scapy.all.IP or
                scapy.all.IPv6.
        intf: the interface (mininet.link.Link) out which the packet should be
                sent.
        '''

        dst = IPAddress( pkt.dst )

        if intf is None:
            if dst not in self.forwardingTable:
                error('%0000.3f Host %s: ERROR:  entry not found for %s\n' % \
                        (self.helper.time( ), self.name, pkt.dst))
                return

            intf, nextHop = self.forwardingTable.getEntry( pkt.dst )

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

    def _setRoute( self, prefix, intf, nextHopIP ):
        if '/' in prefix:
            raise ValueError('Adding prefixes is not supported')
        else:
            self.forwardingTable.addEntry( prefix, intf, nextHopIP )

    def _setRouteKernel( self, prefix, intf, nextHopIP ):
        if '/' in prefix:
            self.setNetRoute( prefix, intf, nextHopIP )
        else:
            self.setHostRoute( prefix, intf, nextHopIP )

    def _configureForwarding( self ):
        pass

    def configureForwarding( self ):
        if self._useKernelForwardingTable:
            self._configureForwarding()
        else:
            self._clearForwardingTable()

class RouterHandler( Layer3Handler ):

    def _configureForwarding( self ):
        self.enableForwarding()

    def _handleNotMyPacket( self, ts, pkt, intf ):
        pkt.ttl -= 1
        if pkt.ttl == 0:
            warning( '%0000.3f Host %s: WARNING: TTL expired for packet destined for %s\n' % \
                    ( self.helper.time( ), self.name, pkt.dst ) )
        else:
            self.sendPacket( )

class HostHandler( Layer3Handler ):
    pass
