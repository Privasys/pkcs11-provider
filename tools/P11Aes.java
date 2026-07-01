// Java SunPKCS11 consumer check: loads the module as a PKCS#11 KeyStore, finds
// the vault AES key (secret keys surface as standalone aliases; private keys
// need certificate objects Java-side, which the module does not serve), and
// drives an AES/GCM encrypt + decrypt through Cipher — C_EncryptInit/C_Encrypt
// and C_DecryptInit/C_Decrypt against the agent (a real vault, or
// tools/mock_agent.py's structural GCM).
//
//   PRIVASYS_PKCS11_VAULT=<vault-id> java tools/P11Aes.java <p11.cfg>
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Enumeration;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

public class P11Aes {
    public static void main(String[] args) throws Exception {
        Provider p = Security.getProvider("SunPKCS11").configure(args[0]);
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null, null);
        String alias = null;
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String a = e.nextElement();
            System.out.println("alias: " + a);
            if (alias == null) alias = a;
        }
        if (alias == null) {
            System.out.println("NO SECRET KEY");
            System.exit(1);
        }
        Key key = ks.getKey(alias, null);
        System.out.println("key: " + key.getAlgorithm() + " / " + key.getClass().getSimpleName());

        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte) 7);
        byte[] pt = "java-vault-roundtrip".getBytes();

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", p);
        enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = enc.doFinal(pt);
        System.out.println("encrypted: " + ct.length + " bytes");

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", p);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] out = dec.doFinal(ct);
        System.out.println("decrypted: '" + new String(out) + "'");
        if (!Arrays.equals(out, pt)) {
            System.out.println("MISMATCH");
            System.exit(1);
        }
        System.out.println("JAVA ROUNDTRIP MATCH");
    }
}
