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
  }
}