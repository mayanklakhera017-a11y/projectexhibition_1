import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class SniExtractor {
  
  public static Optional<String> extractSni(byte[] payload) {
    if (payload == null || payload.length < 5) {
      return Optional.empty();
    }

    ByteBuffer buffer = ByteBuffer.wrap(payload);

    // First byte tells us what type of record is this
    // we only care about handshake records (0x16)
    byte contentType = buffer.get(0);
    if (contentType != 0x16) {
      return Optional.empty();
    }

    // The TLS record header is 5 bytes long (type + version + length),
    // so jump past it to get to the actual handshake data
    if (payload.length < 5 + 4) return Optional.empty();
    buffer.position(5);

    // Inside the handshake, the first byte says what kind of message
    // this is. We only want ClientHello, marked as 0x01.
    byte handshakeType = buffer.get();
    if (handshakeType != 0x01) {
      return Optional.empty();
    }
   
   // Skip past stuff we don't need right now:
   // 3 bytes = handshake length, 2 bytes = TLS version, 32 bytes = random value.
   buffer.position(buffer.position() + 37);

   //session ID length
   if (buffer.remaining() < 1) return Optional.empty();
    int sessionIdLen = Byte.toUnsignedInt(buffer.get());
    if (buffer.remaining() < sessionIdLen + 2) return Optional.empty();
    buffer.position(buffer.position() + sessionIdLen);

    // Same idea for cipher suites — read the length, then skip past them.
    int cipherSuitesLen = Short.toUnsignedInt(buffer.getShort());  
    if (buffer.remaining() < cipherSuitesLen + 1) return Optional.empty();
    buffer.position(buffer.position() + cipherSuitesLen);

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

        // The SNI extension has its own internal structure. The first two bytes
        // are the length of the SNI list, then each entry has a type and length
        buffer.getShort();

        byte nameType = buffer.get();
        if (nameType == 0) {
          int nameLen = Short.toUnsignedInt(buffer.getShort());
          byte[] nameBytes = new byte[nameLen];
          buffer.get(nameBytes);
          String sni = new String(nameBytes, StandardCharsets.UTF_8);
          return Optional.of(sni);
        }

   }else {
    // Skip other extensions
    if (buffer.remaining() < extLen) break;
    buffer.position(buffer.position() + extLen);
  }
}    

return Optional.empty();
  }

      
}