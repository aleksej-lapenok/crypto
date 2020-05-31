package ru.ifmo.lapenok.crypto.a3a5a8;

import java.util.Arrays;
import java.util.Random;

public class A5 {
    private static final Random rnd = new Random();

    public static void main(String[] args) {
        final String input = args[0];
        int[] key = key(input);
        System.out.println("key: " + Arrays.toString(key));

        String encoded = encode(input, key);
        System.out.println(encoded);
        System.out.println(encode(encoded, key));
    }

    public static String encode(String input, int[] key) {
        StringBuilder result = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            result.append((char) (input.charAt(i) ^ key[i]));
        }
        return result.toString();
    }

    public static int[] key(String input) {
        int[] x = new int[19],
                y = new int[22],
                z = new int[23];
        fullArray(x);
        fullArray(y);
        fullArray(z);

        int[] key = new int[input.length()];

        for (int i = 0; i < input.length(); i++) {
            int median = median(x[8], y[10], z[10]);
            if (x[8] == median) {
                int t = x[13] ^ x[16] ^ x[17] ^ x[18];
                shiftRight(x);
                x[0] = t;
            }
            if (y[10] == median) {
                int t = y[20] ^ y[21];
                shiftRight(y);
                y[0] = t;
            }
            if (z[10] == median) {
                int t = z[7] ^ z[20] ^ z[21] ^ z[22];
                shiftRight(z);
                z[0] = t;
            }
            key[i] = x[18] ^ y[21] ^ z[22];
        }

        return key;
    }

    private static void fullArray(int[] array) {
        for (int i = 0; i < array.length; i++) {
            array[i] = rnd.nextInt(2);
        }
    }

    private static void shiftRight(int[] array) {
        int last = array[array.length - 1];
        System.arraycopy(array, 0, array, 1, array.length - 1);
        array[0] = last;
    }

    private static int median(int first, int second, int third) {
        if (first + second + third > 1) {
            return 1;
        } else {
            return 0;
        }
    }
}
