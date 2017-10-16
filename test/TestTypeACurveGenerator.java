import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.junit.*;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestTypeACurveGenerator {

    private BigInteger r;
    private BigInteger h;
    private BigInteger q;

    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = new BigInteger("2");
    private static final BigInteger THREE = new BigInteger("3");
    private static final BigInteger TWELVE = new BigInteger("12");

    @Before
    public void setUp() throws Exception {
        SecureRandom random = new SecureRandom();

        PairingParametersGenerator parametersGenerator = new OurTypeACurveGenerator(random, 256, 1024, false);
        PairingParameters params = parametersGenerator.generate();

        r = params.getBigInteger("r");
        h = params.getBigInteger("h");
        q = params.getBigInteger("q");
    }


    @Test
    public void test4() throws Exception {
        assertThat(r.multiply(h), is(q.add(BigInteger.ONE))); // r * h = q + 1
    }

    @Test
    public void test3() throws Exception {
        assertThat(q.add(ONE).mod(TWELVE), is(ZERO)); // q + 1 % 12 == 0
    }

    @Test
    public void test2() throws Exception {
        assertThat(h.mod(TWELVE), is(ZERO)); // h % 12 == 0
    }

    @Test
    public void test1() throws Exception {
        assertThat(q.mod(THREE), is(TWO)); // q = 2 % 3
    }
}
