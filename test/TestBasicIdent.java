import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class TestBasicIdent {

    @Test
    public void theTest() throws Exception {

        SecureRandom rand = new SecureRandom();

        String id = "hello@world.dk";

        BasicIdent ident = new BasicIdent();
        ident.setup();
        ident.extract(id);

        for (int i = 0; i < 100; i++) {
            String m = new BigInteger(256, rand).toString();
            Ciphertext ciphertext = ident.encrypt(id, m);
            String plaintext = ident.decrypt(id, ciphertext);
            assertTrue(m.equals(plaintext));
        }
    }
}
