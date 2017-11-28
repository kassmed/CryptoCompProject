package com.crypto;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class HIBE2 {

    private Pairing pairing;
    private List<Element> masterKey;
    private Element mapping;

    public List<Element> setup(){
        String filename = "hibe2.properties";

        generate(filename);

        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing(filename);

        List<Element> params = new ArrayList<>();

        // Find generator
        Element g = pairing.getG1().newRandomElement();
        Element ord = pairing.getZr().newElement(pairing.getG1().getOrder());
        Element gmul = g.duplicate().mulZn(ord);
        if (g.isOne() || !gmul.isZero()) { throw new RuntimeException("g is not generator"); }
        params.add(0, g);


        Element x = pairing.getZr().newRandomElement();
        Element gx = g.duplicate().powZn(x);
        if (gx.isZero() || gx.isOne()) { throw new RuntimeException("ill result for sp"); }
        params.add(1, gx);

        Element y = pairing.getZr().newRandomElement();
        Element gy = pairing.getG2().newRandomElement();
        if (gx.isZero() || gx.isOne()) { throw new RuntimeException("ill result for sp"); }
        params.add(2, gy);

        masterKey = Arrays.asList(x, y);

        mapping = pairing.pairing(g, g); // Used in encryption

        return params;
    }

    public List<Element> keyGen(List<Element> params, String identifier){
        Element id = pairing.getZr().newElementFromBytes(identifier.getBytes());
        Element r = pairing.getZr().newRandomElement();
        Element denominator = id.duplicate().add(masterKey.get(1)).add(r.add(masterKey.get(2)));
        if (denominator.isZero()) { return keyGen(params, identifier); }
        Element exponent = pairing.getZr().newOneElement().div(denominator);
        Element k = masterKey.get(0).duplicate().powZn(exponent);
        return Arrays.asList(r, k);
    }

    public ArrayList<Element> encrypt(List<Element> params, String identifier, String message) {
        Element id = pairing.getZr().newElementFromBytes(identifier.getBytes());
        Element m = pairing.getZr().newElementFromBytes(message.getBytes());
        Element s = pairing.getZr().newRandomElement();

        ArrayList<Element> cipher = new ArrayList<>();
        cipher.add(masterKey.get(0).duplicate().powZn(s.duplicate().mul(id)).mul(params.get(1).duplicate().powZn(s)));
        cipher.add(params.get(2).duplicate().powZn(s));
        cipher.add(mapping.powZn(s).mul(m));
        return cipher;
    }

    public String decrypt(List<Element> dID, ArrayList<Element> cipher) {
        Element a = cipher.get(0);
        Element b = cipher.get(1);
        Element c = cipher.get(2);
        Element m = c.duplicate().div(pairing.pairing(a.duplicate().mul(b).powZn(dID.get(0)), dID.get(1)));
        return new String(m.toBytes());
    }

    private PairingParameters generate(String filename) {
        SecureRandom random = new SecureRandom();
        PairingParametersGenerator parametersGenerator = new OurTypeACurveGenerator(random, 256, 1024, false);
        PairingParameters params = parametersGenerator.generate();

        File old = new File(filename);
        boolean deleted = old.delete();
        System.out.println(String.format("%s %s", filename, deleted ? "overwritten" : "created"));

        try (PrintWriter out = new PrintWriter(filename)) {
            out.print(params.toString());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        return params;
    }
}
