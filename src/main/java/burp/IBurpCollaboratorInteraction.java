package burp;

import java.util.Map;

public interface IBurpCollaboratorInteraction {
  String getProperty(String paramString);
  
  Map<String, String> getProperties();
}
