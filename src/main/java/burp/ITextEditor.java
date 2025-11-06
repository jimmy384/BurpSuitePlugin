package burp;

import java.awt.Component;

public interface ITextEditor {
  Component getComponent();
  
  void setEditable(boolean paramBoolean);
  
  void setText(byte[] paramArrayOfbyte);
  
  byte[] getText();
  
  boolean isTextModified();
  
  byte[] getSelectedText();
  
  int[] getSelectionBounds();
  
  void setSearchExpression(String paramString);
}
