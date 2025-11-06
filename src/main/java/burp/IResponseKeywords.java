package burp;

import java.util.List;

public interface IResponseKeywords {
  List<String> getVariantKeywords();
  
  List<String> getInvariantKeywords();
  
  int getKeywordCount(String paramString, int paramInt);
  
  void updateWith(byte[]... paramVarArgs);
}
