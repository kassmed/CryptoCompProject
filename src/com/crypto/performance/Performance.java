package com.crypto.performance;

import com.crypto.*;
import com.google.caliper.AfterExperiment;
import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import com.google.caliper.api.Macrobenchmark;
import com.google.caliper.runner.CaliperMain;
import com.google.caliper.runner.Running;
import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public final class Performance {

    private FullIdent ident;
    private String id;
    private String m;
    private Ciphertext ciphertext;
    private String plaintext;
    private int p = 0;
    private ArrayList<Element> cipher;
    private HIBE2 h;
    private List<Element> params;
    private List<Element> dID;
    private List<String> ids;

    @Param({"32", "64", "128", "256", "512"})
    private int runs;
    private HIBE hh;


    public static void main(String[] args) {
        CaliperMain.main(Performance.class, args);
    }

    @BeforeExperiment
    public void setUp(){
        id = "hello@world.dk";
        ids = Arrays.asList("hello@world.dk");
        SecureRandom rand = new SecureRandom();
        m = new BigInteger(106, rand).toString();
        hh = new HIBE();
        params = hh.setup(ids.size());
        dID = hh.keyGen(params, ids);
        cipher = hh.encrypt(params, ids, m);
    }


    /*@BeforeExperiment
    public void setUp(){
        SecureRandom rand = new SecureRandom();
        id = "hello@world.dk";
        m = new BigInteger(255, rand).toString();
        ident = new FullIdent();
        ident.setup();
        ident.extract(id);
        ciphertext = ident.encrypt(id, m);
    }*/

    @Benchmark
    public void encryptBenchmark(){
        for(int i = 0; i<runs; i++){
            encrypt();
        }
    }

    @Benchmark
    public void decryptBenchmark(){
        for(int i = 0; i<runs; i++){
            decrypt();
        }
    }

    public String encrypt(){

        return ((p++)+""+hh.encrypt(params,ids, m));
    }

    public String decrypt(){
        return ((p++)+""+hh.decrypt(dID, cipher));
    }

    /*
    public String encrypt(){

        return ((p++)+""+ident.encrypt(id, m));
    }

    public String decrypt(){
        return ((p++)+""+ident.decrypt(id, ciphertext));
    }
    */
}
