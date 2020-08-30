class ForwardingTable( object ):
    def __init__( self ):
        self.entries = {}

    def __contains__( self, value ):
        return value in self.entries

    def addEntry( self, prefix, intf, nextHopIP ):
        self.entries[ prefix ] = ( intf, nextHopIP )

    def removeEntry( self, prefix ):
        if prefix in self.prefix:
            del self.entries[ prefix ]

    def getEntry( self, ipAddress ):
        if ipAddress in self.entries:
            return self.entries[ ipAddress ]
        else:
            return ( None, None )
