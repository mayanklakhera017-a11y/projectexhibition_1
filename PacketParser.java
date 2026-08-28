import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;

public class PacketParser {

    public static Optional<PacketTypes.ParsedPacket> parseEthernet(byte[] rawPacket) {
        if (rawPacket == null || rawPacket.length < 14) {
            return Optional.empty();
        }

        ByteBuffer buffer = ByteBuffer.wrap(rawPacket);

        // Ethernet header = 14 bytes (Dst MAC: 6, Src MAC: 6, EtherType: 2)
        int etherType = Short.toUnsignedInt(buffer.getShort(12));

        if (etherType != 0x0800) { // 0x0800 = IPv4
            return Optional.empty(); 
        }

        int ipOffset = 14;
        if (rawPacket.length < ipOffset + 20) return Optional.empty();

        // IPv4 Header Parsing
        byte ihlByte = buffer.get(ipOffset);
        int ihl = (ihlByte & 0x0F) * 4; // Header length in bytes
        int protocolType = Byte.toUnsignedInt(buffer.get(ipOffset + 9));

        String srcIp = String.format("%d.%d.%d.%d",
                Byte.toUnsignedInt(rawPacket[ipOffset + 12]),
                Byte.toUnsignedInt(rawPacket[ipOffset + 13]),
                Byte.toUnsignedInt(rawPacket[ipOffset + 14]),
                Byte.toUnsignedInt(rawPacket[ipOffset + 15]));

        String dstIp = String.format("%d.%d.%d.%d",
                Byte.toUnsignedInt(rawPacket[ipOffset + 16]),
                Byte.toUnsignedInt(rawPacket[ipOffset + 17]),
                Byte.toUnsignedInt(rawPacket[ipOffset + 18]),
                Byte.toUnsignedInt(rawPacket[ipOffset + 19]));

        int l4Offset = ipOffset + ihl;
        PacketTypes.Protocol proto = PacketTypes.Protocol.UNKNOWN;
        int srcPort = 0, dstPort = 0;
        int payloadOffset = l4Offset;

        if (protocolType == 6) { // TCP
            proto = PacketTypes.Protocol.TCP;
            if (rawPacket.length < l4Offset + 20) return Optional.empty();
            srcPort = Short.toUnsignedInt(buffer.getShort(l4Offset));
            dstPort = Short.toUnsignedInt(buffer.getShort(l4Offset + 2));
            int dataOffset = ((buffer.get(l4Offset + 12) >> 4) & 0x0F) * 4;
            payloadOffset = l4Offset + dataOffset;

        } else if (protocolType == 17) { // UDP
            proto = PacketTypes.Protocol.UDP;
            if (rawPacket.length < l4Offset + 8) return Optional.empty();
            srcPort = Short.toUnsignedInt(buffer.getShort(l4Offset));
            dstPort = Short.toUnsignedInt(buffer.getShort(l4Offset + 2));
            payloadOffset = l4Offset + 8;
        }

        byte[] payload = new byte[0];
        if (payloadOffset < rawPacket.length) {
            payload = Arrays.copyOfRange(rawPacket, payloadOffset, rawPacket.length);
        }

        // SNI extraction if present
        Optional<String> sni = SniExtractor.extractSni(payload);

        PacketTypes.FiveTuple tuple = new PacketTypes.FiveTuple(srcIp, dstIp, srcPort, dstPort, proto);
        return Optional.of(new PacketTypes.ParsedPacket(tuple, payload, sni));
    }
}