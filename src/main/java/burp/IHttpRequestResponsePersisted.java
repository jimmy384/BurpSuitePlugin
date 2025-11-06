package burp;

public interface IHttpRequestResponsePersisted extends IHttpRequestResponse {
  @Deprecated
  void deleteTempFiles();
}
