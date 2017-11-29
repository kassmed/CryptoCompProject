package com.crypto;

import it.unisa.dia.gas.jpbc.Element;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TestHIBE2 {

    @Test
    public void theTest() throws Exception {

        HIBE2 h = new HIBE2();
        List<Element> params = h.setup();
        List<Element> dID = h.keyGen(params, "StarLord");

        // Upper limit: 32 bytes while domain is 256 bit
        String message = "qwertyuiopasdfghjklzxcvbnm123456";
        System.out.println("LENGTH: "+message.getBytes().length);
        System.out.println("LENGTH: "+message.length());
        System.out.println(String.format("INPUT: %s", message));
        ArrayList<Element> cipher = h.encrypt(params, "StarLord", message);
        String plain = h.decrypt(dID, cipher);
        System.out.println(String.format("OUTPUT: %s", plain));
    }
}