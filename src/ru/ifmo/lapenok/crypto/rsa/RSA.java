package ru.ifmo.lapenok.crypto.rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class RSA {

    private static final Random rnd = new Random();

    public static void main(String[] args) {
        long p = Long.parseLong(args[0]);
        long q = Long.parseLong(args[1]);

        if (!isSimple(p) || !isSimple(q)) {
            throw new IllegalArgumentException("p & q should be simple");
        }

        long n = p * q;

        if (n > Character.MAX_VALUE) {
            throw new IllegalArgumentException("n = " + n + " is too big");
        }
        long m = (p - 1) * (q - 1);

        long d = d(m);

        long e = e(d, m);

        System.out.println("p=" + p + ", q=" + q + ", n=" + n + ", m=" + m + ", d=" + d + ", e=" + e);

        String input = args[2];

        String encoded = encode(input, e, n);
        System.out.println(encoded);

        System.out.println(decode(encoded, d, n));
    }

    public static String encode(String input, long e, long n) {
        List<Long> result = new ArrayList<>();

        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);

            BigInteger bi = BigInteger.valueOf(ch).pow((int) e);
            bi = bi.mod(BigInteger.valueOf(n));

            result.add(bi.longValue());
        }

        StringBuilder resultStr = new StringBuilder(result.size() * 4);
        for (long value : result) {
            resultStr.append((char) value);
        }
        return resultStr.toString();
    }

    public static String decode(String input, long d, long n) {
        List<Long> inp = new ArrayList<>();
        for (int i = 0; i < input.length(); i++) {
            inp.add((long) input.charAt(i));
        }

        StringBuilder result = new StringBuilder();

        for (long item : inp) {
            BigInteger bi = BigInteger.valueOf(item);
            bi = bi.pow((int) d);

            bi = bi.mod(BigInteger.valueOf(n));

            result.append((char) bi.intValue());
        }

        return result.toString();
    }

    private static long e(long d, long m) {
        long e = 10;
        while (true) {
            if (e * d % m == 1) {
                break;
            } else {
                e++;
            }
        }
        return e;
    }

    public static long d(long m) {
        long d = m - 1;
        for (long i = 2; i <= m; i++) {
            if (m % i == 0 && d % i == 0) {
                d--;
                i = 1;
            }
        }
        return d;
    }

    public static boolean isSimple(long n) {
        if (n < 2) {
            return false;
        }
        if (n == 2) {
            return true;
        }

        for (long i = 2; i < n; i++) {
            if (n % i == 0) {
                return false;
            }
        }
        return true;
    }

    public static Key generateKey() {
        BigInteger p, q, n, phi, e;
        do {
            p = BigInteger.valueOf(RunSmallExponentHack.getPrime());
            q = BigInteger.valueOf(RunSmallExponentHack.getPrime());
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            e = BigInteger.valueOf(rnd.nextInt(phi.intValue()));
        }
        while (!e.gcd(phi).equals(BigInteger.ONE) || n.compareTo(BigInteger.valueOf(Character.MAX_VALUE)) > 0);

        BigInteger d = e.modInverse(phi);
        return new Key(d.longValue(), n.longValue(), e.longValue());
    }

    public static class Key {
        private final long d;
        private final long n;
        private final long e;

        public Key(long d, long n, long e) {
            this.d = d;
            this.n = n;
            this.e = e;
        }

        public long getD() {
            return d;
        }

        public long getN() {
            return n;
        }

        public long getE() {
            return e;
        }

        @Override
        public String toString() {
            return "Key{" +
                    "d=" + d +
                    ", n=" + n +
                    ", e=" + e +
                    '}';
        }
    }
}
