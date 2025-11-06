package burp;

import java.util.List;

public interface IBurpCollaboratorClientContext {
  String generatePayload(boolean paramBoolean);
  
  List<IBurpCollaboratorInteraction> fetchAllCollaboratorInteractions();
  
  List<IBurpCollaboratorInteraction> fetchCollaboratorInteractionsFor(String paramString);
  
  List<IBurpCollaboratorInteraction> fetchAllInfiltratorInteractions();
  
  List<IBurpCollaboratorInteraction> fetchInfiltratorInteractionsFor(String paramString);
  
  String getCollaboratorServerLocation();
}
