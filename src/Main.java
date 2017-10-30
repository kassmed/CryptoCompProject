import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Main {

    static Map<String, Element> knownKeys = new HashMap<>();

    public static void main(String[] args) {

        SecureRandom rand = new SecureRandom();

        String id = "hello@world.dk";

        BasicIdent ident = new BasicIdent();
        ident.setup();
        ident.extract(id);

        for (int i = 0; i < 100; i++) {
            String m = new BigInteger(256, rand).toString();
            Ciphertext ciphertext = ident.encrypt(id, m);
            String plaintext = ident.decrypt(id, ciphertext);
            System.out.println(m.equals(plaintext));
        }
    }
}
