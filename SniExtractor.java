import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class SniExtractor {

    public static Optional<String> extractSni(byte[] payload) {
        if (payload == null || payload.length < 5) {
            return Optional.empty();
        }

        ByteBuffer buffer = ByteBuffer.wrap(payload);

        // Check TLS Record Type (0x16 = Handshake)
        byte contentType = buffer.get(0);
        if (contentType != 0x16) {
            return Optional.empty();
        }

        // Skip Record Header (5 bytes: ContentType[1], Version[2], Length[2])
        if (payload.length < 5 + 4) return Optional.empty();
        buffer.position(5);

        // Check Handshake Type (0x01 = Client Hello)
        byte handshakeType = buffer.get();
        if (handshakeType != 0x01) {
            return Optional.empty();
        }

        // Skip Handshake Length (3 bytes) + Version (2 bytes) + Random (32 bytes)
        buffer.position(buffer.position() + 37);

        // Session ID length
        if (buffer.remaining() < 1) return Optional.empty();
        int sessionIdLen = Byte.toUnsignedInt(buffer.get());
        if (buffer.remaining() < sessionIdLen + 2) return Optional.empty();
        buffer.position(buffer.position() + sessionIdLen);

        // Cipher Suites length
        int cipherSuitesLen = Short.toUnsignedInt(buffer.getShort());
        if (buffer.remaining() < cipherSuitesLen + 1) return Optional.empty();
        buffer.position(buffer.position() + cipherSuitesLen);

        // Compression Methods length
        int compressionLen = Byte.toUnsignedInt(buffer.get());
        if (buffer.remaining() < compressionLen + 2) return Optional.empty();
        buffer.position(buffer.position() + compressionLen);

        // Extensions Length
        int extensionsLen = Short.toUnsignedInt(buffer.getShort());
        if (buffer.remaining() < extensionsLen) return Optional.empty();

        int endExtensions = buffer.position() + extensionsLen;

        // Loop through TLS extensions
        while (buffer.position() + 4 <= endExtensions) {
            int extType = Short.toUnsignedInt(buffer.getShort());
            int extLen = Short.toUnsignedInt(buffer.getShort());

            if (extType == 0) { // Extension 0 = Server Name Indication (SNI)
                if (buffer.remaining() < extLen) return Optional.empty();
                
                // SNI List Length (2 bytes)
                buffer.getShort(); 
                // Server Name Type (1 byte, 0 = host_name)
                byte nameType = buffer.get();
                if (nameType == 0) {
                    int nameLen = Short.toUnsignedInt(buffer.getShort());
                    if (buffer.remaining() < nameLen) {
                        return Optional.empty(); // truncated/malformed packet, bail out safely
                    }
                    byte[] nameBytes = new byte[nameLen];
                    buffer.get(nameBytes);
                    return Optional.of(new String(nameBytes, StandardCharsets.UTF_8));
                }
            } else {
                // Skip other extensions
                if (buffer.remaining() < extLen) break;
                buffer.position(buffer.position() + extLen);
            }
        }

        return Optional.empty();
    }
}