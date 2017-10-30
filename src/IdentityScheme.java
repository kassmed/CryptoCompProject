

public interface IdentityScheme {

    void setup();

    void extract(String id);

    Ciphertext encrypt(String id, String msg);

    String decrypt(String id, Ciphertext ciphertext);
}
