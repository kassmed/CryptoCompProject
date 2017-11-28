package com.crypto;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;

public class Ciphertext {

    private Element u;
    private BigInteger v;
    private BigInteger w;

    @Deprecated
    public Ciphertext(Element u, byte[] v) {
        this.u = u;
        this.v = new BigInteger(v);
    }

    public Ciphertext(Element u, BigInteger v, BigInteger w) {
        this.u = u;
        this.v = v;
        this.w = w;
    }

    public Element getU() {
        return u;
    }

    public BigInteger getV() {
        return v;
    }

    public BigInteger getW() {
        return w;
    }

    @Override
    public String toString(){
        return String.format("%s-%s-%s", u,v,w);
    }
}
