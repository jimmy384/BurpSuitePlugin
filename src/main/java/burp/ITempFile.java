package burp;

public interface ITempFile {
  byte[] getBuffer();
  
  @Deprecated
  void delete();
}
