package burp;

import java.awt.Component;

public interface IMessageEditor {
  Component getComponent();
  
  void setMessage(byte[] paramArrayOfbyte, boolean paramBoolean);
  
  byte[] getMessage();
  
  boolean isMessageModified();
  
  byte[] getSelectedData();
  
  int[] getSelectionBounds();
}
