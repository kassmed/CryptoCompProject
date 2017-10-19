import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.security.MessageDigest;

public class Hash2Algorithm implements HashAlgorithm<byte[]> {
    private final Field G1;
    private final MessageDigest sha256;
    private int n;

    public Hash2Algorithm(Field G1, MessageDigest sha256, int n) {
        this.G1 = G1;
        this.sha256 = sha256;
        this.n = n;
    }

    @Override
    public byte[] hash(String input) {
        return sha256.digest(input.getBytes());
    }
}
