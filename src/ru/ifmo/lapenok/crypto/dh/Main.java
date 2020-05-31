package ru.ifmo.lapenok.crypto.dh;

import java.math.BigInteger;
import java.util.Random;

import ru.ifmo.lapenok.crypto.hash.Sha256;
import ru.ifmo.lapenok.crypto.rsa.RSA;

public class Main {
    public static final Random rnd = new Random();

    public static void main(String[] args) {
        BigInteger P = BigInteger.probablePrime(50, rnd);
        final BigInteger G = BigInteger.probablePrime(7, rnd);
//        BigInteger pv1d1 = P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
//
//        while (pv1d1.isProbablePrime(10)) {
//            P = BigInteger.probablePrime(50, rnd);
//        }

//        System.out.println("pv1d1: " + pv1d1 + " is prime: " + pv1d1.isProbablePrime(10));
        System.out.println("P=" + P + " G=" + G);

        final BigInteger a = BigInteger.valueOf(Math.abs(rnd.nextLong()));
        final BigInteger b = BigInteger.valueOf(Math.abs(rnd.nextLong()));

        System.out.println("secret alice = " + a + ", secret bob = " + b);

        final BigInteger A = G.modPow(a, P);
        final BigInteger B = G.modPow(b, P);

        System.out.println("A = " + A + " B = " + B);

        final RSA.Key aliceKey = RSA.generateKey();
        final String signedA = RSA.encode(A.toString(), aliceKey.getD(), aliceKey.getN());
        System.out.println("Alice key: " + aliceKey + " signed value = " + signedA);

        final RSA.Key bobKey = RSA.generateKey();
        final String signedB = RSA.encode(B.toString(), bobKey.getD(), bobKey.getN());
        System.out.println("Alice key: " + bobKey + " signed value = " + signedB);

        final BigInteger Rb = new BigInteger(RSA.decode(signedA, aliceKey.getE(), aliceKey.getN()));
        final BigInteger Ra = new BigInteger(RSA.decode(signedB, bobKey.getE(), bobKey.getN()));

        System.out.println("Ra= " + Ra + " Rb="+Rb);

        final BigInteger Ka = Ra.modPow(a, P);
        final BigInteger Kb = Rb.modPow(b, P);

        System.out.println("Ka = " + Ka + " Kb = " + Kb + " equals = "+ Ka.equals(Kb));

        System.out.println("Key = " + Ka);
    }

}
