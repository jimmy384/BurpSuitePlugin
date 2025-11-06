package burp;

public interface IIntruderPayloadProcessor {
  String getProcessorName();
  
  byte[] processPayload(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3);
}
