import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class HIBE {

    private PairingParameters pairingParameters;
    private Pairing pairing;
    private Element masterKey;

    public List<Element> setup(int l){
        String filename = "hibe.properties";
        pairingParameters = generate(filename);
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing(filename);

        //add extra g,g1,g2
        List<Element> params = new ArrayList<>(l+3);

        Element alpha = pairing.getZr().newRandomElement();
        Element g = pairing.getG1().newRandomElement();
        Element ord = pairing.getZr().newElement(pairing.getG1().getOrder());
        Element gmul = pairing.getG1().newElement(g).mulZn(ord);
        if (g.isOne() || !gmul.isZero()) { throw new RuntimeException("g is not generator"); }
        params.add(0, g);

        Element g1 = pairing.getG1().newElement(g).powZn(alpha);
        if (g1.isZero() || g1.isOne()) { throw new RuntimeException("ill result for sp"); }
        params.add(1, g1);
        Element g2 = pairing.getG2().newRandomElement();
        Element ord2 = pairing.getZr().newElement(pairing.getG2().getOrder());
        Element gmul2 = pairing.getG2().newElement(g2).mulZn(ord2);
        if (g2.isOne() || !gmul2.isZero()) { throw new RuntimeException("g2 is not generator"); }
        params.add(2, g2);

        for(int i = 0; i < l; i++){
            params.add(pairing.getG1().newRandomElement());
        }

        masterKey = pairing.getG2().newElement(g2).powZn(alpha);

        return params;
    }

    public List<Element> keyGen(List<Element> params, List<String> ids){

        List<Element> xs = ids.stream()
                .map(id -> pairing.getG1().newElementFromBytes(id.getBytes()))
                .collect(Collectors.toList());

        List<Element> h = params.subList(3, params.size());
        List<Element> randoms = new ArrayList<>();
        for(int i = 0; i < h.size(); i++){
            randoms.add(pairing.getZr().newRandomElement());
        }

        List<Element> products = new ArrayList<>();
        for (int k = 0; k < h.size(); k++) {
            Element g1 = pairing.getG1().newElement(params.get(1));
            products.add(fj(xs.get(k), g1, h.get(k)).powZn(randoms.get(k)));
        }

        Element product = products.stream().reduce(pairing.getG1().newOneElement(), (x, y) -> {
            return pairing.getG1().newElement(x).mul(pairing.getG1().newElement(y));
        });

        List<Element> dID = new ArrayList<>();
        dID.add(pairing.getG2().newElement(masterKey).mul(product));

        dID.addAll(randoms.stream()
                .map(rnd -> pairing.getG1().newElement(params.get(0)).powZn(rnd))
                .collect(Collectors.toList()));

        return dID;
    }

    private Element fj(Element x, Element g1, Element h) {
        return g1.powZn(x).mul(h);
    }


    public ArrayList<Element> encrypt(List<Element> params, List<String> id, String message) {
        Element m = pairing.getG1().newElementFromBytes(message.getBytes());

        System.out.println(m.getClass().getName());

        System.out.println(pairing.pairing(pairing.getG1().newRandomElement(), pairing.getG1().newRandomElement()).getClass());
        System.out.println(m);

        Element s = pairing.getZr().newRandomElement();
        ArrayList<Element> c = new ArrayList<>(params.size() - 1);
        c.add(m.mulZn(pairing.pairing(params.get(1), params.get(2)).powZn(s)));
        c.add(pairing.getG1().newElement(params.get(0)).powZn(s));

        List<Element> xs = id.stream()
                .map(identifier -> pairing.getG1().newElementFromBytes(identifier.getBytes()))
                .collect(Collectors.toList());

        for (int k = 3; k < params.size(); k++) {
            Element g1 = pairing.getG1().newElement(params.get(1));
            c.add(fj(xs.get(k-3), g1, params.get(k)).powZn(s));
        }
        return c;
    }

    public String decrypt(List<Element> dID, ArrayList<Element> cipher) {
        Element dom = pairing.getGT().newOneElement();
        for (int j = 2; j < cipher.size(); j++) {
            dom = dom.mul(pairing.pairing(cipher.get(j), dID.get(j-1)));
        }
        Element div = pairing.pairing(cipher.get(1), dID.get(0));
        Element m = cipher.get(0).mulZn((dom.div(div)));

        System.out.println(m.getClass().getName());
        System.out.println(m);

        return new String(m.toBytes());
    }

    private PairingParameters generate(String filename) {
        SecureRandom random = new SecureRandom();
        PairingParametersGenerator parametersGenerator = new OurTypeACurveGenerator(random, 256, 1024, false);
        PairingParameters params = parametersGenerator.generate();

        File old = new File(filename);
        boolean deleted = old.delete();
        System.out.println(String.format("%s %s", filename, deleted ? "overwritten" : "created"));

        try (PrintWriter out = new PrintWriter(filename)) {
            out.print(params.toString());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        return params;
    }
}
