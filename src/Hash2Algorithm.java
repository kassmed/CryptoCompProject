import java.security.MessageDigest;

public class Hash2Algorithm {

    private final MessageDigest sha256;
    private int n;

    public Hash2Algorithm(MessageDigest sha256, int n) {
        this.sha256 = sha256;
        this.n = n;
    }

    public byte[] hash(byte[] input) {
        return String.format("%"+n+"s", new String(sha256.digest(input))).getBytes();
    }
}
