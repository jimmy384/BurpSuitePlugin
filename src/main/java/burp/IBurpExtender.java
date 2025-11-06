package burp;

public interface IBurpExtender {
  void registerExtenderCallbacks(IBurpExtenderCallbacks paramIBurpExtenderCallbacks);
  
  void processHttpMessage(int paramInt, boolean paramBoolean, IHttpRequestResponse paramIHttpRequestResponse);
  
  byte[] getResponse();
  
  IHttpService getHttpService();
}
