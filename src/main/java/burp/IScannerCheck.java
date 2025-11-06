package burp;

import java.util.List;

public interface IScannerCheck {
  List<IScanIssue> doPassiveScan(IHttpRequestResponse paramIHttpRequestResponse);
  
  List<IScanIssue> doActiveScan(IHttpRequestResponse paramIHttpRequestResponse, IScannerInsertionPoint paramIScannerInsertionPoint);
  
  int consolidateDuplicateIssues(IScanIssue paramIScanIssue1, IScanIssue paramIScanIssue2);
}
