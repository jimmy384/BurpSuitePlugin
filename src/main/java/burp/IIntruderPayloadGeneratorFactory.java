package burp;

public interface IIntruderPayloadGeneratorFactory {
  String getGeneratorName();
  
  IIntruderPayloadGenerator createNewInstance(IIntruderAttack paramIIntruderAttack);
}
