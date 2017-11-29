package com.crypto;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class HIBE2 {

    private Pairing pairing;
    private List<Element> masterKey;
    private Element mapping;
    private Charset charset = Charset.forName("UTF-8");

    public List<Element> setup(){
        String filename = "hibe2.properties";

        generate(filename);

        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing(filename);

        List<Element> params = new ArrayList<>();

        // Find generator
        // TODO: Randomize
        //Element g = pairing.getG1().newRandomElement();
        Element g = pairing.getG1().newElementFromBytes(new byte[] {8, 86, -76, -85, 4, -64, 28, -99, 125, 105, 44, -17, 97, -73, -68, 113, -59, 97, 120, -3, 31, -17, 39, 126, -113, -9, -35, -72, -121, -83, 49, 7, -101, 7, -116, 77, -124, -85, -39, 66, 7, 18, 78, -76, -30, 84, -11, 52, -99, -103, 58, -115, 16, -8, -124, 96, -4, 23, -121, -69, 64, -90, 30, 45, -13, -59});
        // Element g = pairing.getG1().newElementFromBytes("fjknm".getBytes());
        Element ord = pairing.getZr().newElement(pairing.getG1().getOrder());
        Element gmul = g.duplicate().mulZn(ord);
        if (g.isOne() || !gmul.isZero()) { throw new RuntimeException("g is not generator"); }
        params.add(0, g);


        // TODO: Randomize
        //Element x = pairing.getZr().newRandomElement();
        Element x = pairing.getZr().newElement(BigInteger.TEN);
        Element gx = g.duplicate().powZn(x);
        if (gx.isZero() || gx.isOne()) { throw new RuntimeException("ill result for sp"); }
        params.add(1, gx);

        // TODO: Randomize
        //Element y = pairing.getZr().newRandomElement();
        Element y = pairing.getZr().newElement(BigInteger.TEN);
        Element gy = g.duplicate().powZn(y);
        if (gx.isZero() || gx.isOne()) { throw new RuntimeException("ill result for sp"); }
        params.add(2, gy);

        masterKey = Arrays.asList(x, y);

        mapping = pairing.pairing(g, g); // Used in encryption

        return params;
    }

    public List<Element> keyGen(List<Element> params, String identifier){
        Element id = pairing.getZr().newElementFromBytes(identifier.getBytes());

        // TODO: Randomize
        // Element r = pairing.getZr().newRandomElement();
        Element r = pairing.getZr().newOneElement();

        Element x = masterKey.get(0);
        Element y = masterKey.get(1);
        Element g = params.get(0);

        Element denominator = id.duplicate().add(x).add(r.duplicate().mulZn(y)); // id + x + ry
        if (denominator.isZero()) { return keyGen(params, identifier); }
        Element k = g.duplicate().powZn(denominator.invert());
        return Arrays.asList(r, k);
    }

    public ArrayList<Element> encrypt(List<Element> params, String identifier, String message) {
        Element id = pairing.getZr().newElementFromBytes(identifier.getBytes(charset));
        Element m = pairing.getGT().newElementFromBytes(message.getBytes());
        System.out.println("INPUT: " + m);

        // TODO: Randomize
        // Element s = pairing.getZr().newRandomElement();
        Element s = pairing.getZr().newOneElement();

        ArrayList<Element> cipher = new ArrayList<>();

        Element g = params.get(0);
        Element gx = params.get(1);
        Element gy = params.get(2);

        cipher.add(g.duplicate().powZn(s.duplicate().mulZn(id)).mul(gx.powZn(s)));
        cipher.add(gy.duplicate().powZn(s));
        cipher.add(mapping.duplicate().powZn(s).mul(m));
        return cipher;
    }

    public String decrypt(List<Element> dID, ArrayList<Element> cipher) {
        Element a = cipher.get(0);
        Element b = cipher.get(1);
        Element c = cipher.get(2);
        Element r = dID.get(0);
        Element k = dID.get(1);

        Element left = a.duplicate().mul(b.duplicate().powZn(r));
        Element right = k;

        Element e = pairing.pairing(left, right);
        Element m = c.duplicate().div(e);
        System.out.println("OUTPUT: " + m);

        return new String(m.toBytes(), charset).replace("\u0000", ""); /*
        byte[] bytes = m.toBytes();
        return IntStream.range(0, bytes.length)
                .mapToObj(i -> bytes[i] == 0 ? "": new String(new byte[] {bytes[i]}, charset))
                .reduce("", (xx, yy) -> xx + yy);*/
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
