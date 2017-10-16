import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Test {

    public static void main(String[] args) {

        int zeros = 0;
        for (int i = 0; i < 10; i++) {
            SecureRandom random = new SecureRandom();

            PairingParametersGenerator parametersGenerator = new OurTypeACurveGenerator(random, 256, 1024, true);
            PairingParameters params = parametersGenerator.generate();

            // Step 1
            Pairing pairing = PairingFactory.getPairing(params, random);

            // Step 2
            Element s = pairing.getZr().newRandomElement();
            while (s.isZero()) { s = pairing.getZr().newRandomElement(); }

            Element p = getGenerator(pairing.getG1());
            Element pPub = p.mulZn(s);

            System.out.println("s: " + s);
            System.out.println("p: " + p);
            System.out.println("pPub: " + pPub);

            // TODO: Why is pPub always zero ???
            if (pPub.isZero()) {
                zeros += 1;
            }
        }
        System.out.println("Zeros: " +zeros);

    }

    public static boolean isGenerator(Element e, BigInteger order) {
        return !e.isZero() && e.pow(order).isZero();
    }

    public static Element getGenerator(Field f) {
        Element g = f.newRandomElement();
        while (!isGenerator(g, f.getOrder())) {
            //System.out.println("Element is not generator (not expected)");
            g = f.newRandomElement();
        }
        return g;
    }

}
