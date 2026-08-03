
public class pkttyp
{
    public enum Protocol
    {
        UNKNOWN,
        TCP,
        UDP,
        ICMP
    }
    public static class fiveTuple
    {
        private String scrIp;
        private String dstIp;
        private int scrPort;
        private int dstPort;
        private Protocol protocol;

        public fiveTuple(String scrIp, String dstIp, int scrPort, int dstPort, Protocol protocol)
        {
            this.scrIp = scrIp;
            this.dstIp = dstIp;
            this.scrPort = scrPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
        }

        public String getSrcIP()
        {
            return scrIp;
        }

        public String getDstIP()
        {
            return dstIp;
        }

        public int getSrcPort()
        {
            return scrPort;
        }

        public int getDstPort()
        {
            return dstPort;
        }

        public Protocol getProtocol()
        {
            return protocol;
        }
    }
}

