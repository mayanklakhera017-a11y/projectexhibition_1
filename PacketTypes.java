import java.util.Optional;

public class PacketTypes {

    public enum Protocol {
        UNKNOWN,
        TCP,
        UDP,
        ICMP
    }

    public static class FiveTuple {
        private String srcIp;
        private String dstIp;
        private int srcPort;
        private int dstPort;
        private Protocol protocol;

        public FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, Protocol protocol) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
        }

        // Getters
        public String getSrcIp() { return srcIp; }
        public String getDstIp() { return dstIp; }
        public int getSrcPort() { return srcPort; }
        public int getDstPort() { return dstPort; }
        public Protocol getProtocol() { return protocol; }

        @Override
        public String toString() {
            return String.format("%s:%d -> %s:%d [%s]", srcIp, srcPort, dstIp, dstPort, protocol);
        }
    }

    public static class ParsedPacket {
        private FiveTuple tuple;
        private byte[] payload;
        private Optional<String> sni;

        public ParsedPacket(FiveTuple tuple, byte[] payload, Optional<String> sni) {
            this.tuple = tuple;
            this.payload = payload;
            this.sni = sni;
        }

        public FiveTuple getTuple() { return tuple; }
        public byte[] getPayload() { return payload; }
        public Optional<String> getSni() { return sni; }
    }
}