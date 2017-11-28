package com.crypto;

import com.google.caliper.runner.CaliperMain;
import org.junit.Test;

import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.api.VmOptions;


import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

@VmOptions("-XX:CICompilerCount=2")
public final class TestBasicIdent {

    private BasicIdent ident;
    private String id;

    public static void main(String[] args) {
        CaliperMain.main(TestBasicIdent.class, args);
    }


    @BeforeExperiment
    public void setUp(){
        id = "hello@world.dk";
        ident = new BasicIdent();
        ident.setup();
        ident.extract(id);
    }

    @Benchmark
    public void timeMe(){
        System.out.println("i ran");
        SecureRandom rand = new SecureRandom();
        String m = new BigInteger(256, rand).toString();
        Ciphertext ciphertext = ident.encrypt(id, m);
        String plaintext = ident.decrypt(id, ciphertext);
    }

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
