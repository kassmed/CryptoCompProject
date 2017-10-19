import it.unisa.dia.gas.jpbc.Element;

public class Ciphertext {

    Element left;
    byte[] right;

    public Ciphertext(Element left, byte[] right) {
        this.left = left;
        this.right = right;
    }

    public Element getLeft() {
        return left;
    }

    public byte[] getRight() {
        return right;
    }
}
