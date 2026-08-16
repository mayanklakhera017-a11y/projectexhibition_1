
public class pkttyp
{
    //list of protocols
    public enum Protocol
    {
        UNKNOWN, // protocol we dont recognize
        TCP, // Transmission Control Protocol(reliable, connection)
        UDP,// User Datagram Protocol(unreliable, connectionless)
        ICMP // Internet Control Message Protocol(used for things like ping)
    }

    //class stores basic info that identifies a network connection
    //five pieces of information that uniquely identify a connection source ip, destn ip, source port, destn port, protocol
    public static class fiveTuple
    {
        private String scrIp;
        private String dstIp;
        private int scrPort;
        private int dstPort;
        private Protocol protocol;

        public fiveTuple(String scrIp, String dstIp, int scrPort, int dstPort, Protocol protocol)
        {
            this.scrIp = scrIp;// source ip address
            this.dstIp = dstIp;// destination ip address
            this.scrPort = scrPort;// source port number
            this.dstPort = dstPort;// destination port number
            this.protocol = protocol;// protocol used for the connection
        }

    //getter methods to access the private fields of the fiveTuple class
        public String getSrcIP()
        {
            return scrIp;
        }
    // returns the destination IP address 
        public String getDstIP()
        {
            return dstIp;
        }

    // returns the source port number
        public int getSrcPort()
        {
            return scrPort;
        }

    // returns the destination port number
        public int getDstPort()
        {
            return dstPort;
        }

    // returns the protocol used for the connection
        public Protocol getProtocol()
        {
            return protocol;
        }


        @Override
        public String toString()
        {
            return String.format("%s:%d -> %s:%d [%s]", scrIp, scrPort, dstIp, dstPort, protocol);
        }
    }

// class that represents a packet that has been analyzed
    public static class parsedPacket
    {
        private fiveTuple tuple;
        private byte[] payload;
        private String sni;

        public parsedPacket(fiveTuple tuple, byte[] payload, String sni)
        {
            this.tuple = tuple;
            this.payload = payload;
            this.sni = sni;
        }
        public fiveTuple getTuple()
        {
            return tuple;
        }
        public byte[] getPayload()
        { 
            return payload;
        }
        public String getSni()
        {  
             return sni;
        }
    }
}

