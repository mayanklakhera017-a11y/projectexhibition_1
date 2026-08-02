
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
    }
}

