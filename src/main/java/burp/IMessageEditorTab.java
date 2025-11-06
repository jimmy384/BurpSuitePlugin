package burp;

import java.awt.Component;

public interface IMessageEditorTab {
  String getTabCaption();
  
  Component getUiComponent();
  
  boolean isEnabled(byte[] paramArrayOfbyte, boolean paramBoolean);
  
  void setMessage(byte[] paramArrayOfbyte, boolean paramBoolean);
  
  byte[] getMessage();
  
  boolean isModified();
  
  byte[] getSelectedData();
}
