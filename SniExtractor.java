import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
 
public class   SniExtractor
{
  public static Optional<String> extractSni(byte[]payload)
  {
      if(payload == null || payload.length < 5)
      {   return Optional.empty();
      }
  }
  
}