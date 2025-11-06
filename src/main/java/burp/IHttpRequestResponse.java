package burp;

public interface IHttpRequestResponse {
  byte[] getRequest();
  
  void setRequest(byte[] paramArrayOfbyte);
  
  byte[] getResponse();
  
  void setResponse(byte[] paramArrayOfbyte);
  
  String getComment();
  
  void setComment(String paramString);
  
  String getHighlight();
  
  void setHighlight(String paramString);
  
  IHttpService getHttpService();
  
  void setHttpService(IHttpService paramIHttpService);
}
