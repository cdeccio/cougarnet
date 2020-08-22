import binascii
import socket


#/usr/include/netinet/in.h
IPPROTO_TCP = 6
IPPROTO_UDP = 17

class IPAddressString( str ):
    pass

IPAddress = IPAddressString

IP_BROADCAST = IPAddress( '255.255.255.255' )
