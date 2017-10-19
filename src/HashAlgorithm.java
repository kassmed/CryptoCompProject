
public interface HashAlgorithm<T> {
    T hash(String input);
    T hash(byte[] input);
}
