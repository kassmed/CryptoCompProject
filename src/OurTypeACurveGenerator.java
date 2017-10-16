//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.io.Base64;
import it.unisa.dia.gas.plaf.jpbc.util.math.BigIntegerUtils;
import java.math.BigInteger;
import java.security.SecureRandom;

public class OurTypeACurveGenerator implements PairingParametersGenerator {
    protected SecureRandom random;
    protected int rbits;
    protected int qbits;
    protected boolean generateCurveFieldGen;

    public OurTypeACurveGenerator(SecureRandom random, int rbits, int qbits, boolean generateCurveFieldGen) {
        this.random = random;
        this.rbits = rbits;
        this.qbits = qbits;
        this.generateCurveFieldGen = generateCurveFieldGen;
    }

    public OurTypeACurveGenerator(int rbits, int qbits) {
        this(new SecureRandom(), rbits, qbits, false);
    }

    public OurTypeACurveGenerator(int rbits, int qbits, boolean generateCurveFieldGen) {
        this(new SecureRandom(), rbits, qbits, generateCurveFieldGen);
    }

    public PairingParameters generate() {
        boolean found = false;
        BigInteger h = null;
        boolean var8 = false;

        BigInteger q;
        BigInteger r;
        int exp1;
        int exp2;
        byte sign0;
        byte sign1;
        do {
            r = BigInteger.ZERO;
            if(this.random.nextInt(2147483647) % 2 != 0) {
                exp2 = this.rbits - 1;
                sign1 = 1;
            } else {
                exp2 = this.rbits;
                sign1 = -1;
            }

            r = r.setBit(exp2);
            q = BigInteger.ZERO;
            exp1 = this.random.nextInt(2147483647) % (exp2 - 1) + 1;
            q = q.setBit(exp1);
            if(sign1 > 0) {
                r = r.add(q);
            } else {
                r = r.subtract(q);
            }

            if(this.random.nextInt(2147483647) % 2 != 0) {
                sign0 = 1;
                r = r.add(BigInteger.ONE);
            } else {
                sign0 = -1;
                r = r.subtract(BigInteger.ONE);
            }

            if(r.isProbablePrime(10)) {
                for(int i = 0; i < 10; ++i) {
                    q = BigInteger.ZERO;
                    int bit = this.qbits - this.rbits - 4 + 1;
                    if(bit < 3) {
                        bit = 3;
                    }

                    q = q.setBit(bit);
                    // h = BigIntegerUtils.getRandom(q, this.random).multiply(BigIntegerUtils.TWELVE);
                    h = BigIntegerUtils.TWELVE;
                    // (h * r) - 1 = q
                    q = h.multiply(r).subtract(BigInteger.ONE);
                    if(q.isProbablePrime(10)) {
                        found = true;
                        break;
                    }
                }
            }
        } while(!found);

        PropertiesParameters params = new PropertiesParameters();
        params.put("type", "a");
        params.put("q", q.toString());
        params.put("r", r.toString());
        params.put("h", h.toString());
        params.put("exp1", String.valueOf(exp1));
        params.put("exp2", String.valueOf(exp2));
        params.put("sign0", String.valueOf(sign0));
        params.put("sign1", String.valueOf(sign1));
        if(this.generateCurveFieldGen) {
            Field Fq = new ZrField(this.random, q);
            CurveField curveField = new CurveField(this.random, Fq.newOneElement(), Fq.newZeroElement(), r, h);
            params.put("genNoCofac", Base64.encodeBytes(curveField.getGenNoCofac().toBytes()));
        }

        return params;
    }
}
