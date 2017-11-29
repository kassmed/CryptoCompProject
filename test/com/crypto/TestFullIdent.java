package com.crypto;

import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class TestFullIdent {

    @Test
    public void theTest() throws Exception {

        SecureRandom rand = new SecureRandom();

        String id = "hello@world.dk";

        FullIdent ident = new FullIdent();
        ident.setup();
        ident.extract(id);

        for (int i = 0; i < 100; i++) {
            String m = new BigInteger(255, rand).toString();
            // String m = "qwertyuiopasdfghjklzxcvbnm123456";
            Ciphertext ciphertext = ident.encrypt(id, m);
            String plaintext = ident.decrypt(id, ciphertext);
            //System.out.println("input: "+ m);
            //System.out.println("output: " + plaintext);
            assertTrue(m.equals(plaintext));
        }
    }
}
