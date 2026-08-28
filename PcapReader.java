import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PcapReader implements AutoCloseable {
    private final DataInputStream dis;
    private final boolean isLittleEndian;

    public PcapReader(String filePath) throws IOException {
        this.dis = new DataInputStream(new FileInputStream(filePath));

        // Read PCAP Global Header (24 bytes)
        int magicNumber = dis.readInt();
        if (magicNumber == 0xa1b2c3d4) {
            isLittleEndian = false;
        } else if (magicNumber == 0xd4c3b2a1) {
            isLittleEndian = true;
        } else {
            throw new IOException("Invalid or unsupported PCAP file format magic number.");
        }

        // Skip remaining 20 bytes of Global Header
        dis.skipBytes(20);
    }

    public byte[] readNextPacket() throws IOException {
        if (dis.available() <= 0) {
            return null;
        }

        // Read Packet Header (16 bytes: ts_sec, ts_usec, incl_len, orig_len)
        int tsSec = readInt32();
        int tsUsec = readInt32();
        int inclLen = readInt32();
        int origLen = readInt32();

        byte[] packetData = new byte[inclLen];
        dis.readFully(packetData);
        return packetData;
    }

    private int readInt32() throws IOException {
        int val = dis.readInt();
        return isLittleEndian ? Integer.reverseBytes(val) : val;
    }

    @Override
    public void close() throws IOException {
        if (dis != null) dis.close();
    }
}