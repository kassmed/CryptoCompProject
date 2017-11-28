package com.crypto.performance;

import com.crypto.BasicIdent;
import com.crypto.Ciphertext;
import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import com.google.caliper.runner.CaliperMain;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public final class Performance {

    private BasicIdent ident;
    private String id;
    private String m;
    private Ciphertext ciphertext;

    public static void main(String[] args) {
        CaliperMain.main(Performance.class, args);
    }


    @BeforeExperiment
    public void setUp(){
        id = "hello@world.dk";
        m = "27576127993684171947355412918724850833146200166215438679060632812043035631385";
        ident = new BasicIdent();
        ident.setup();
        ident.extract(id);
        ciphertext = ident.encrypt(id, m);
    }

    @Benchmark
    public void encrypt(){
        ciphertext = ident.encrypt(id, m);
    }

    @Benchmark
    public void decrypt(){
        String plaintext = ident.decrypt(id, ciphertext);
    }

}
