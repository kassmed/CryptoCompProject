import it.unisa.dia.gas.jpbc.Element;
import org.junit.Test;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class TestHIBE {

    @Test
    public void theTest() throws Exception {

        List<String> id = Arrays.asList("Hello", "World");

        HIBE h = new HIBE();
        List<Element> params = h.setup(id.size());
        List<Element> dID = h.keyGen(params, id);
        String message = "Bye world";
        ArrayList<Element> cipher = h.encrypt(params, id, message);
        String plain = h.decrypt(dID, cipher);
        System.out.println(plain);
    }
}