import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.security.MessageDigest;

public class Hash1Algorithm implements HashAlgorithm<Element> {

    private Field G1;
    private MessageDigest sha256;

    public Hash1Algorithm(Field G1, MessageDigest sha256) {
        this.G1 = G1;
        this.sha256 = sha256;
    }

    @Override
    public Element hash(String input) {
        byte[] hash = sha256.digest(input.getBytes());
        return G1.newElementFromBytes(hash);
    }
}
