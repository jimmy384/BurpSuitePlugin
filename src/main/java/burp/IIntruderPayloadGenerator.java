package burp;

public interface IIntruderPayloadGenerator {
  boolean hasMorePayloads();
  
  byte[] getNextPayload(byte[] paramArrayOfbyte);
  
  void reset();
}
