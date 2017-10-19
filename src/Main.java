import it.unisa.dia.gas.jpbc.Element;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Main {

    static Map<String, Element> knownKeys = new HashMap<>();

    public static void main(String[] args) {

        SecureRandom rand = new SecureRandom();

        String id = "hello@world.dk";

        Setup setup = new Setup();
        extract(id, setup);

        for (int i = 0; i < 100; i++) {
            String m = new BigInteger(256, rand).toString();
            Ciphertext ciphertext = encrypt(m, id, setup);
            String plaintext = decrypt(id, ciphertext, setup);
            System.out.println(m.equals(plaintext));
        }
    }

    private static void extract(String id, Setup setup) {
        Element qID = (Element) setup.getHash1().hash(id);
        Element dID = qID.mulZn(setup.getMasterSecret());
        knownKeys.put(id, dID);
    }

    private static Ciphertext encrypt(String msg, String id, Setup setup) {
        Element qID = (Element) setup.getHash1().hash(id);
        Element r = setup.getZR().newRandomElement();
        Element rP = setup.getPublicKey().mulZn(r);

        BigInteger m = new BigInteger(msg.getBytes());

        byte[] b = setup.getPairing().pairing(qID, setup.getPublicKey()).powZn(r).toBytes();
        BigInteger hash = new BigInteger((byte[]) setup.getHash2().hash(b));

        return new Ciphertext(rP, m.xor(hash).toByteArray());
    }

    private static String decrypt(String id, Ciphertext ciphertext, Setup setup) {
        Element e = setup.getPairing().pairing(knownKeys.get(id), ciphertext.getLeft());
        byte[] hash = (byte[]) setup.getHash2().hash(e.toBytes());
        BigInteger m = new BigInteger(ciphertext.getRight()).xor(new BigInteger(hash));
        return new String(m.toByteArray());
    }
}
