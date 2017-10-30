import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;
import java.security.MessageDigest;

public class Hash3Algorithm {

    private final MessageDigest sha256;
    private final int n;
    private final Field zq;


    public Hash3Algorithm(MessageDigest sha256, int n, Field zq) {
        this.sha256 = sha256;
        this.n = n;
        this.zq = zq;
    }

    public Element hash(byte[] s1, byte[] s2) {
        return hash(new BigInteger(s1), new BigInteger(s2));
    }

    public Element hash(BigInteger s1, BigInteger s2) {
        byte[] hash = sha256.digest(s1.xor(s2).toByteArray());
        return zq.newElementFromHash(hash, 0, n);
    }
}
