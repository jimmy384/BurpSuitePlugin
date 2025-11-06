package burp;

import java.util.List;

public interface IResponseVariations {
  List<String> getVariantAttributes();
  
  List<String> getInvariantAttributes();
  
  int getAttributeValue(String paramString, int paramInt);
  
  void updateWith(byte[]... paramVarArgs);
}
