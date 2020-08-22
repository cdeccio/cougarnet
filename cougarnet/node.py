from mininet.log import debug

from scapy.all import Ether, UDP

from .ether import ETH_P_IP, ETH_P_IPV6
from .mac import ETH_BROADCAST
from .ip import IPPROTO_TCP, IPPROTO_UDP, IP_BROADCAST


class NoMatchingMethod(Exception):
    pass

class BaseHandler( object ):
    PROTOHANDLERS = {
    }
    allowForward = False

    def __init__( self, node ):
        self.node = node
        self.protocolHandlers = None
        self._installDefaultHandlers()

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
            debug( '*** %s: No handler for protocol 0x%000x at layer %s: %s\n' % \
                    ( self.node.name, proto, layer, repr( pkt ) ) )
            return None
        return handler( ts, pkt, intf )

    def _handleFrame( self, ts, frame, intf ):
        raise NotImplemented

class Layer3Handler( BaseHandler ):
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
    allowForward = False

    def allowPackets( self, proto, port ):
        #TODO bind/firewall protocols based on interface, not node; for now, it's okay
        for intf in self.node.ports:
            self.node.cmd( 'iptables', '-A', 'INPUT', '-i', intf.name, '-p', proto, '--dport', str( port ), '-j', 'DROP' )

    def _handleFrame( self, ts, frame, intf ):
        frame = Ether( frame )
        if frame.dst.lower() not in (intf.mac.lower(), ETH_BROADCAST):
            # drop
            debug( '*** %s: Not my packet: %s\n' % \
                    ( self.node.name, repr( frame ) ) )
            return None
        return self._handleNext( 'ETH', frame.type, ts, frame.payload, intf )

    def _handleIP( self, ts, pkt, intf ):
        ipv4Addrs = [ intf.ip for intf in self.node.ports if intf.ip is not None ]
        ipv6Addrs = [ intf.ip6 for intf in self.node.ports if intf.ip6 is not None ]
        ipv6LLAddrs = [ intf.ip6ll for intf in self.node.ports if intf.ip6ll is not None ]

        print('foobar...', type(IP_BROADCAST))
        if pkt.dst in ipv4Addrs or \
                pkt.dst in ipv6Addrs or \
                pkt.dst == IP_BROADCAST:
            self._handleNext( 'IP', pkt.proto, ts, pkt, intf )

        #TODO decrement TTL
        #TODO handle forwarding
        #TODO handle drop

    def _handleUDP( self, ts, pkt, intf ):
        return self._handleNext( 'UDP', pkt.dport, ts, pkt, intf )

    def _handleTCP( self, ts, pkt, intf ):
        return self._handleNext( 'TCP', ( pkt.dport, pkt.sport ), ts, pkt, intf )

    def printDatagramPayload( self, ts, pkt, intf ):
        print( '*** (%0.3f) %s: received UDP datagram: %s' % ( ts, self.node.name, bytes( pkt.getlayer( UDP ).payload ).decode( 'utf-8' ) ) ) 

class RouterHandler( Layer3Handler ):
    allowForward = True

class HostHandler( Layer3Handler ):
    allowForward = False
