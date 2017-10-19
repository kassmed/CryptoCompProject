import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Setup {

    private final Field G1;
    private final Field G2;
    private final Field GT;

    private HashAlgorithm hash1;
    private HashAlgorithm hash2;

    private static final int n = 256;

    private final Element generator;
    private final Element publicKey;
    private final Element masterSecret;

    private final Pairing pairing;
    private final PairingParameters pairingParameters;


    public Setup() {
        String filename = "default.properties";
        pairingParameters = generate(filename);
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing(filename);

        G1 = pairing.getG1();
        G2 = pairing.getG2();
        GT = pairing.getGT();

        Element s = pairing.getZr().newRandomElement();
        if (s.isZero() || s.isOne()) { throw new RuntimeException("s is not generator"); }
        masterSecret = s;

        Element p = G1.newRandomElement();
        if (p.isZero() || p.isOne()) { throw new RuntimeException("p is not generator"); }
        generator = p;

        Element sP = p.mulZn(s);
        if (sP.isZero() || sP.isOne()) { throw new RuntimeException("ill result for sp"); }
        publicKey = sP;

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            hash1 = new Hash1Algorithm(G1, sha256);
            hash2 = new Hash2Algorithm(G1, sha256, n);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        }
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

    public Field getG1() {
        return G1;
    }

    public Field getG2() {
        return G2;
    }

    public Field getGT() {
        return GT;
    }

    public HashAlgorithm getHash1() {
        return hash1;
    }

    public HashAlgorithm getHash2() {
        return hash2;
    }

    public static int getN() {
        return n;
    }

    public Element getGenerator() {
        return generator;
    }

    public Element getPublicKey() {
        return publicKey;
    }

    public Element getMasterSecret() {
        return masterSecret;
    }

    public Pairing getPairing() {
        return pairing;
    }

    public PairingParameters getPairingParameters() {
        return pairingParameters;
    }
}
