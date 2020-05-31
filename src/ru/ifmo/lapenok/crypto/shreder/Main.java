package ru.ifmo.lapenok.crypto.shreder;

import java.math.BigInteger;
import java.util.Random;
import java.util.stream.IntStream;

import ru.ifmo.lapenok.crypto.des.Des;

public class Main {
    private static final Random rnd = new Random();

    public static void main(String[] args) throws IllegalAccessException {
        final String keyA = generateKey(32);
        final String keyB = generateKey(32);
        final BigInteger Ra = BigInteger.valueOf(rnd.nextLong());
        final BigInteger Rb = BigInteger.valueOf(rnd.nextLong());

        final String aliceToTrandInitial = "Alice; Bob; " + Ra;
        System.out.println("Alice to Trand: " + aliceToTrandInitial);

        final String sessionKey = generateKey(32);
        final long ts = System.currentTimeMillis();
        final long ttl = 1000; //1 sec
        final String strForBob = sessionKey + "; " + ts + "; " + ttl + "; alice";
        System.out.println("strForBob: " + strForBob);
        final String encodedForBob = Des.encode(strForBob, keyB);
        final String strForAlice = sessionKey + "; " + ts + "; " + ttl + "; " + encodedForBob + "; " + Ra + "; bob";
        System.out.println("strForAlice: " + strForAlice);
        final String encodedForAlice = Des.encode(strForAlice, keyA);
        System.out.println("Trand to Alice: " + encodedForAlice);

        final String[] aliceFromTrand = Des.decode(encodedForAlice, keyA).split("; ");
        final String sessionKeyAlice = aliceFromTrand[0];
        final long sessionTsAlice = Long.parseLong(aliceFromTrand[1]);
        final long sessionTtlAlice = Long.parseLong(aliceFromTrand[2]);
        final String aliceToBob = aliceFromTrand[3];
        final BigInteger RaTrand = BigInteger.valueOf(Long.parseLong(aliceFromTrand[4]));
        System.out.println("sessionKeyAlice = " + sessionKeyAlice +
                " sessionTsAlice=" + sessionTsAlice +
                " sessionTTlAlice=" + sessionTtlAlice +
                " raFromTrand=" + RaTrand);

        assert RaTrand.equals(Ra);

        System.out.println("Alice to Bob: " + aliceToBob);

        final String[] bobFromAlice = Des.decode(aliceToBob, keyB).split("; ");
        final String sessionKeyBob = bobFromAlice[0];
        final long sessionTsBob = Long.parseLong(bobFromAlice[1]);
        final long sessionTtlBob = Long.parseLong(bobFromAlice[2]);
        System.out.println("sessionKeyBob = " + sessionKeyBob +
                " sessionTsBob=" + sessionTsBob +
                " sessionTTlBob=" + sessionTtlBob);
        final String BobToAlice = Des.encode(Rb.toString(), sessionKeyBob);

        final BigInteger aliceFromBob = BigInteger.valueOf(Long.parseLong(Des.decode(BobToAlice, sessionKeyAlice)));
        System.out.println("aliceFromBobNumber: " + aliceToBob);

        final BigInteger aliceToBobNumber = aliceFromBob.subtract(BigInteger.ONE);
        System.out.println("aliceToBobNumber: " + aliceToBobNumber);
        final String aliceToBobEncoded = Des.encode(aliceToBobNumber.toString(), sessionKeyAlice);

        final BigInteger bobFromAliceNumber = BigInteger.valueOf(Long.parseLong(Des.decode(aliceToBobEncoded, sessionKeyBob)));
        System.out.println("bobFromAliceNumber: " + bobFromAliceNumber);

        assert bobFromAliceNumber.equals(Rb.subtract(BigInteger.ONE));
        System.out.println("Connection established, sessionKey: " + sessionKey);
    }

    private static String generateKey (int length) {
        final int[] codes = IntStream.range (0, length).map (__ -> rnd.nextInt (Character.MAX_VALUE)).toArray ();
        return new String (codes, 0, codes.length);
    }
}
