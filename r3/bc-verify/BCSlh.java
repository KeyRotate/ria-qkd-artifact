import java.security.SecureRandom;
import java.nio.file.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SLHDSASigner;

public class BCSlh {
  static SLHDSAParameters pick(String n){
    switch(n){
      case "sha2_128s": return SLHDSAParameters.sha2_128s;
      case "sha2_128f": return SLHDSAParameters.sha2_128f;
      case "sha2_192s": return SLHDSAParameters.sha2_192s;
      case "sha2_256s": return SLHDSAParameters.sha2_256s;
      default: throw new RuntimeException("unknown "+n);
    }
  }
  public static void main(String[] a) throws Exception {
    String mode=a[0], name=a[1];
    SLHDSAParameters prm=pick(name);
    SLHDSASigner s=new SLHDSASigner();
    String pre="bc_"+name;
    if(mode.equals("gen")){
      SLHDSAKeyPairGenerator g=new SLHDSAKeyPairGenerator();
      g.init(new SLHDSAKeyGenerationParameters(new SecureRandom(), prm));
      AsymmetricCipherKeyPair kp=g.generateKeyPair();
      SLHDSAPublicKeyParameters pub=(SLHDSAPublicKeyParameters)kp.getPublic();
      SLHDSAPrivateKeyParameters priv=(SLHDSAPrivateKeyParameters)kp.getPrivate();
      byte[] msg=new byte[32]; new SecureRandom().nextBytes(msg);
      s.init(true, priv);
      byte[] sig=s.generateSignature(msg);
      Files.write(Paths.get(pre+"_pk.bin"), pub.getEncoded());
      Files.write(Paths.get(pre+"_msg.bin"), msg);
      Files.write(Paths.get(pre+"_sig.bin"), sig);
      System.out.println("BC gen "+name+": pk="+pub.getEncoded().length+" sig="+sig.length);
    } else {
      byte[] pk=Files.readAllBytes(Paths.get(a[2]));
      byte[] msg=Files.readAllBytes(Paths.get(a[3]));
      byte[] sig=Files.readAllBytes(Paths.get(a[4]));
      SLHDSAPublicKeyParameters pub=new SLHDSAPublicKeyParameters(prm, pk);
      s.init(false, pub);
      boolean ok=s.verifySignature(msg, sig);
      System.out.println("BC verify "+name+" <"+a[2]+">: "+(ok?"OK":"FAIL"));
    }
  }
}
