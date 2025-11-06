package burp;

public interface ISessionHandlingAction {
  String getActionName();
  
  void performAction(IHttpRequestResponse paramIHttpRequestResponse, IHttpRequestResponse[] paramArrayOfIHttpRequestResponse);
}
