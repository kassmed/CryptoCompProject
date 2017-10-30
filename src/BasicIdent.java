import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class BasicIdent implements IdentityScheme {

    private PairingParameters pairingParameters;
    private Pairing pairing;

    private Hash1Algorithm hash1;
    private Hash2Algorithm hash2;

    private Element masterSecret;
    private Element generator;
    private Element publicKey;
    private Map<String, Element> knownKeys = new HashMap<>();

    @Override
    public void setup() {
        String filename = "basic.properties";
        pairingParameters = generate(filename);
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing(filename);

        Element s = pairing.getZr().newRandomElement();
        if (s.isZero() || s.isOne()) { throw new RuntimeException("s is not generator"); }
        masterSecret = s;

        Element p = pairing.getG1().newRandomElement();
        if (p.isZero() || p.isOne()) { throw new RuntimeException("p is not generator"); }
        generator = p;

        Element sP = p.mulZn(s);
        if (sP.isZero() || sP.isOne()) { throw new RuntimeException("ill result for sp"); }
        publicKey = sP;

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            hash1 = new Hash1Algorithm(pairing.getG1(), sha256);
            hash2 = new Hash2Algorithm(sha256, 256);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    @Override
    public void extract(String id) {
        Element qID = hash1.hash(id);
        Element dID = qID.mulZn(masterSecret);
        knownKeys.put(id, dID);
    }

    @Override
    public Ciphertext encrypt(String id, String msg) {
        Element qID = hash1.hash(id);
        Element r = pairing.getZr().newRandomElement();
        Element rP = publicKey.mulZn(r);

        BigInteger m = new BigInteger(msg.getBytes());

        byte[] b = pairing.pairing(qID, publicKey).powZn(r).toBytes();
        BigInteger hash = new BigInteger(hash2.hash(b));

        return new Ciphertext(rP, m.xor(hash).toByteArray());
    }

    @Override
    public String decrypt(String id, Ciphertext ciphertext) {
        Element e = pairing.pairing(knownKeys.get(id), ciphertext.getLeft());
        byte[] hash = hash2.hash(e.toBytes());
        BigInteger m = new BigInteger(ciphertext.getRight()).xor(new BigInteger(hash));
        return new String(m.toByteArray());
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
