import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
public class pcapReader implements AutoCloseable{
    private final DataInputStream dis;
    private final boolean isLittleEndian; // true if pcap file is stored in little endian format

    public pcapReader(String filePath) throws IOException {
        this.dis = new DataInputStream(new FileInputStream(filePath));

        // The first 4 bytes of pcap file is the magic number which is used to determine the endianness of the file
       // every pcap file starts with a 24 byte global header
        int magicNumber = dis.readInt();
        if (magicNumber == 0xa1b2c3d4) {
            isLittleEndian = false; // file is in big endian format no flip needed
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
            return null; //no more packets to read left in the file
        }

        // Read Packet Header (16 bytes: ts_sec, ts_usec, incl_len, orig_len)
        int tsSec = readInt32(); // timestamp seconds
        int tsUsec = readInt32();// timestamp microseconds
        int inclLen = readInt32();// number of bytes of packet saved in file
        int origLen = readInt32();// how many bytes the packet would have been if it were not truncated

    // Read Packet Data
        byte[] packetData = new byte[inclLen];
        dis.readFully(packetData);
        return packetData;
    }
    // read 4 bytes from the DataInputStream and return it as an int, taking into account the endianness of the pcap file
    private int readInt32() throws IOException {
        int val = dis.readInt();
        return isLittleEndian ? Integer.reverseBytes(val) : val;
    }

    @Override
    public void close() throws IOException {    
        if (dis != null) dis.close(); // release the file when we are finished
    }
}