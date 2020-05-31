package ru.ifmo.lapenok.crypto.rsa;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RunSmallExponentHack {//Хастада
    private static final int EXP = 3;
    private static final Random rnd = new Random();

    public static void main(String[] args) {

        String message = args[0];

        final List<Output> ciphers = new ArrayList<>();
        final Set<Long> knownsNs = new HashSet<>();

        while (ciphers.size() < 20) {
            final Output output = encode(message, EXP);
            if (output.n - 500 <= 0 && !knownsNs.contains(output.n)) {
                knownsNs.add(output.n);
                ciphers.add(output);
            }
        }

        long bounds = ciphers.stream().map(it -> it.n).limit(3).reduce(1L, (a, b) -> a * b);

        for (int i = 0; i < ciphers.get(0).output.length(); i++) {
            final int index = i;
            Set<Long> options = ciphers.stream().map(it -> {
                long code = it.output.charAt(index);
                long steps = bounds / it.n;
                long step = it.n;

                return Stream.iterate(code, it2 -> it2 + step).limit(steps)
                        .collect(Collectors.toSet());
            }).reduce((res, cur) -> {
                res.retainAll(cur);
                return res;
            }).get();

            if (options.size() != 1) {
                List<Long> rest = options.stream().sorted().distinct().limit(20).collect(Collectors.toList());
                System.out.println();
                System.out.println("Failed to hack: " + rest);
            }

            final char m = options.stream().map(v -> (char)Math.round(Math.pow(v.doubleValue(), 1.0/3)))
                    .findFirst().orElseThrow(IllegalStateException::new);
            System.out.print(m);
        }


    }

    private static Output encode(String input, long e) {
        long p, q, n, d, m;
        do {
            p = getPrime();
            q = getPrime();

            n = p * q;

            m = (p - 1) * (q - 1);

        } while (ru.ifmo.lapenok.crypto.first.Main.gcd(e, m) != 1);


        d = RSA.d(m);

//        System.out.println(p + " " + q);

        return new Output(RSA.encode(input, e, n),
                n);
    }

    public static long getPrime() {
        while (true) {
            long result = rnd.nextInt(512);
            if (RSA.isSimple(result)) {
                return result;
            }
        }
    }

    private static class Output {
        final String output;
//        final long d;
        final long n;

        public Output(String output, long n) {
            this.output = output;
            this.n = n;
        }
    }
}
