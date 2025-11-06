package burp;

import java.net.URL;
import java.util.List;

public interface IExtensionHelpers {
  IRequestInfo analyzeRequest(IHttpRequestResponse paramIHttpRequestResponse);
  
  IRequestInfo analyzeRequest(IHttpService paramIHttpService, byte[] paramArrayOfbyte);
  
  IRequestInfo analyzeRequest(byte[] paramArrayOfbyte);
  
  IResponseInfo analyzeResponse(byte[] paramArrayOfbyte);
  
  IParameter getRequestParameter(byte[] paramArrayOfbyte, String paramString);
  
  String urlDecode(String paramString);
  
  String urlEncode(String paramString);
  
  byte[] urlDecode(byte[] paramArrayOfbyte);
  
  byte[] urlEncode(byte[] paramArrayOfbyte);
  
  byte[] base64Decode(String paramString);
  
  byte[] base64Decode(byte[] paramArrayOfbyte);
  
  String base64Encode(String paramString);
  
  String base64Encode(byte[] paramArrayOfbyte);
  
  byte[] stringToBytes(String paramString);
  
  String bytesToString(byte[] paramArrayOfbyte);
  
  int indexOf(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, boolean paramBoolean, int paramInt1, int paramInt2);
  
  byte[] buildHttpMessage(List<String> paramList, byte[] paramArrayOfbyte);
  
  byte[] buildHttpRequest(URL paramURL);
  
  byte[] addParameter(byte[] paramArrayOfbyte, IParameter paramIParameter);
  
  byte[] removeParameter(byte[] paramArrayOfbyte, IParameter paramIParameter);
  
  byte[] updateParameter(byte[] paramArrayOfbyte, IParameter paramIParameter);
  
  byte[] toggleRequestMethod(byte[] paramArrayOfbyte);
  
  IHttpService buildHttpService(String paramString1, int paramInt, String paramString2);
  
  IHttpService buildHttpService(String paramString, int paramInt, boolean paramBoolean);
  
  IParameter buildParameter(String paramString1, String paramString2, byte paramByte);
  
  IScannerInsertionPoint makeScannerInsertionPoint(String paramString, byte[] paramArrayOfbyte, int paramInt1, int paramInt2);
  
  IResponseVariations analyzeResponseVariations(byte[]... paramVarArgs);
  
  IResponseKeywords analyzeResponseKeywords(List<String> paramList, byte[]... paramVarArgs);
}
