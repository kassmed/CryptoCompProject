package com.crypto;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.security.MessageDigest;

public class Hash4Algorithm {

    private MessageDigest sha256;

    public Hash4Algorithm(MessageDigest sha256) {
        this.sha256 = sha256;
    }

    public BigInteger hash(byte[] s1) {
        return new BigInteger(sha256.digest(s1));
    }

    public BigInteger hash(Element sigma) {
        return hash(sigma.toBigInteger());
    }

    public BigInteger hash(BigInteger sigma) {
        return hash(sigma.toString().getBytes());
    }
}
