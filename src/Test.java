import com.sun.tools.classfile.Attribute;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Test {

    public static void main(String[] args) {

        String input = "hello@world.dk";
        String filename = "test.properties";


        for (int i = 0; i < 100; i++) {

            generate(filename);

            PairingFactory.getInstance().setUsePBCWhenPossible(true);
            Pairing pairing = PairingFactory.getPairing(filename);

            // Step 1

            // Step 2
            Element s = pairing.getZr().newRandomElement();
            if (s.isZero() || s.isOne()) { throw new RuntimeException("s is not generator"); }

            Element p = pairing.getG1().newRandomElement();
            if (p.isZero() || p.isOne()) { throw new RuntimeException("p is not generator"); }

            Element sp = p.mulZn(s);
            if (sp.isZero() || sp.isOne()) { throw new RuntimeException("ill result for sp"); }

            // TODO: Why cant we convert curve element to bigInteger?

            MessageDigest sha256 = null;
            try {
                sha256 = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                System.exit(-1);
            }

            BigInteger hash = new BigInteger(sha256.digest(input.getBytes()));

            // TODO: Convert hash to G1 element

        }
    }

    private static void generate(String filename) {

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
    }

}
