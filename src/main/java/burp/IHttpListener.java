package burp;

public interface IHttpListener {
  void processHttpMessage(int paramInt, boolean paramBoolean, IHttpRequestResponse paramIHttpRequestResponse);
  
  byte[] getRequest();
}
