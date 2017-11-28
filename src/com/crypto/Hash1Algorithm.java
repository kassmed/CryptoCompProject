package com.crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.security.MessageDigest;

public class Hash1Algorithm {

    private Field G1;
    private MessageDigest sha256;

    public Hash1Algorithm(Field G1, MessageDigest sha256) {
        this.G1 = G1;
        this.sha256 = sha256;
    }

    public Element hash(String input) {
        return hash(input.getBytes());
    }

    public Element hash(byte[] input) {
        byte[] hash = sha256.digest(input);
        return G1.newElementFromBytes(hash);
    }
}
