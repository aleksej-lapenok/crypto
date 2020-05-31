package ru.ifmo.lapenok.crypto.des;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Des {
    private static final int sizeBlock = 8;//8 байт
    private static final int quantityOfRounds = 16;

    private static int[] IP = new int[]{
            58, 50, 42, 34, 26, 18, 10, 02,
            60, 52, 44, 36, 28, 20, 12, 04,
            62, 54, 46, 38, 30, 22, 14, 06,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 01,
            59, 51, 43, 35, 27, 19, 11, 03,
            61, 53, 45, 37, 29, 21, 13, 05,
            63, 55, 47, 39, 31, 23, 15, 07};
    private static int[] IP_REV = new int[]{
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 07, 47, 15, 55, 23, 63, 31,
            38, 06, 46, 14, 54, 22, 62, 30,
            37, 05, 45, 13, 53, 21, 61, 29,
            36, 04, 44, 12, 52, 20, 60, 28,
            35, 03, 43, 11, 51, 19, 59, 27,
            34, 02, 42, 10, 50, 18, 58, 26,
            33, 01, 41, 9, 49, 17, 57, 25,
    };
    private static int[] E = new int[]{
            32, 01, 02, 03, 04, 05,
            04, 05, 06, 07, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 01,
    };
    private static int[] G = new int[]{
            57, 49, 41, 33, 25, 17, 9,
            01, 58, 50, 42, 34, 26, 18,
            10, 02, 59, 51, 43, 35, 27,
            19, 11, 03, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            07, 62, 54, 46, 38, 30, 22,
            14, 06, 61, 53, 45, 37, 29,
            21, 13, 05, 28, 20, 12, 04,
    };
    private static int[] H = new int[]{
            14, 17, 11, 24, 01, 05,
            03, 28, 15, 06, 21, 10,
            23, 19, 12, 04, 26, 8,
            16, 07, 27, 20, 13, 02,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32,
    };
    private static int[] P = new int[]{
            16, 07, 20, 21,
            29, 12, 28, 17,
            01, 15, 23, 26,
            05, 18, 31, 10,
            02, 8, 24, 14,
            32, 27, 03, 9,
            19, 13, 30, 06,
            22, 11, 04, 25,
    };
    private static int[] ITERATION_SHIFT = new int[]{
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    private static int[] ITERATION_INF = new int[]{
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };
    private static int[][][] sbox = new int[][][]{
            {
                    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            {
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            {
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            {
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
    };


    public static void main(String[] args) throws IllegalAccessException {
        final String encoded = encode(args[0], args[1]);
        System.out.println(encoded);
        System.out.println(decode(encoded, args[1]));
    }

    public static String encode(String text, String key) throws IllegalAccessException {
        String s = fillString(text);

        List<Boolean>[] blocks = blocks(s);

        key = cutKey(key, sizeBlock);

        List<Boolean> keyBlock = key(block(key));

        for (int j = 0; j < quantityOfRounds; j++) {
            List<Boolean> iterationKey = mix(keyBlock, H);
            for (int i = 0; i < blocks.length; i++) {
                blocks[i] = encodeOne(blocks[i], iterationKey);
            }
            keyBlock = shiftLeftKey(keyBlock, j);
        }

        return printStr(blocks);
    }

    public static String decode(String text, String key) throws IllegalArgumentException, IllegalAccessException {
        List<Boolean>[] blocks = blocks(text);

        key = cutKey(key, sizeBlock);

        List<Boolean> keyBlock = key(block(key));

        for (int j = 0; j < quantityOfRounds - 1; j++) {
            keyBlock = shiftLeftKey(keyBlock, j);
        }

        for (int j = 0; j < quantityOfRounds; j++) {
            List<Boolean> iterationKey = mix(keyBlock, H);
            for (int i = 0; i < blocks.length; i++) {
                blocks[i] = decodeOne(blocks[i], iterationKey);
            }
            if (j != quantityOfRounds - 1) {
                keyBlock = shiftRightKey(keyBlock, quantityOfRounds - j - 2);
            }
        }

        return printStr(blocks).trim();
    }

    private static String printStr(List<Boolean>[] blocks) {
        StringBuilder output = new StringBuilder(blocks.length * blocks[0].size());
        for (List<Boolean> block : blocks) {
            block(block).forEach(output::append);
        }
        return output.toString();
    }

    private static String cutKey(String key, int length) throws IllegalAccessException {
        if (key.length() > length) {
            return key.substring(0, length);
        } else {
            StringBuilder keyResult = new StringBuilder();
            keyResult.append(key);
            while (keyResult.length() < length) {
                keyResult.append((char) 0);
            }
            return keyResult.toString();
        }
    }

    private static String fillString(String text) {
        StringBuilder str = new StringBuilder(text.length() + sizeBlock);
        str.append(text);
        while (str.length() % sizeBlock != 0) {
            str.append(" ");
        }
        return str.toString();
    }

    private static List<Boolean>[] blocks(String text) {
        final List<Boolean>[] blocks = new List[Math.max(text.length() / sizeBlock, 1)];

        int lengthOfBlock = text.length() / blocks.length;

        for (int i = 0; i < blocks.length; i++) {
            String block = text.substring(i * lengthOfBlock, (i + 1) * lengthOfBlock);
            blocks[i] = block(block);
        }
        return blocks;
    }

    private static List<Boolean> block(String block) {
        final char[] blockArray = block.toCharArray();
        List<Boolean> bytes = new ArrayList<>();
        for (char ch : blockArray) {
            bytes.addAll(toBytes(ch, 8));
        }
        return mix(bytes, IP);
    }

    private static List<Boolean> key(List<Boolean> key) {
        return Arrays.stream(G).map(it -> it - 1).mapToObj(key::get).collect(Collectors.toList());
    }

    //invert-1
    private static List<Character> block(List<Boolean> block) {
        block = mix(block, IP_REV);

        final Boolean[] charArray = block.toArray(new Boolean[0]);
        final int[] output = new int[charArray.length / 8];
        for (int i = 0; i < charArray.length / 8; i++) {
            for (int j = 0; j < 8; j++) {
                int one = charArray[8 * i + j] ? 1 : 0;
                output[i] = (output[i] << 1) + one;
            }
        }
        return Arrays.stream(output).mapToObj(it -> (char) it).collect(Collectors.toList());
    }

    private static List<Boolean> encodeOne(List<Boolean> block, List<Boolean> key) {
        List<Boolean> L = new ArrayList<>(block.subList(0, block.size() / 2));
        List<Boolean> R = new ArrayList<>(block.subList(block.size() / 2, block.size()));

        R.addAll(XOR(L, f(R, key)));
        return R;
    }

    private static List<Boolean> decodeOne(List<Boolean> block, List<Boolean> key) {
        List<Boolean> L = new ArrayList<>(block.subList(0, block.size() / 2));
        List<Boolean> R = new ArrayList<>(block.subList(block.size() / 2, block.size()));

        List<Boolean> result = XOR(f(L, key), R);
        result.addAll(L);
        return result;
    }

    private static List<Boolean> XOR(List<Boolean> text, List<Boolean> key) {
        List<Boolean> result = new ArrayList<>();
        if (text.size() > key.size()) {
            throw new RuntimeException(new IllegalArgumentException());
        }
        for (int i = 0; i < text.size(); i++) {
            result.add((text.get(i) ^ key.get(i)));
        }
        return result;
    }

    private static List<Boolean> f(List<Boolean> first, List<Boolean> key) {
        List<Boolean> expansionBlock = expansion(first);//48 bit
        List<Boolean> e = XOR(expansionBlock, key);//48 bit
        List<Boolean> result = new ArrayList<>();
        for (int i = 0; i < 8; i++) {//8 block by 6 bit
            int[][] s = sbox[i];
            List<Integer> b =
                    e.subList(i * 6, (i + 1) * 6).stream().map(Des::booleanToInt).collect(Collectors.toList());
            int firstIdx = (b.get(0) << 1) + b.get(5);
            int secondIdx = (b.get(1) << 3) + (b.get(2) << 2) + (b.get(3) << 1) + b.get(4);

            result.addAll(toBytes(s[firstIdx][secondIdx], 4));

        }
        return mix(result, P);
    }

    private static int booleanToInt(boolean b) {
        return b ? 1 : 0;
    }

    private static boolean intToBoolean(int a) {
        return a == 1;
    }

    private static List<Boolean> toBytes(int number, int cnt) {
        List<Boolean> result = new ArrayList<>();
        for (int i = 0; i < cnt; i++) {
            int b = number % 2;
            number /= 2;
            result.add(intToBoolean(b));
        }
        Collections.reverse(result);
        return result;
    }

    private static List<Boolean> expansion(List<Boolean> key) {
        return mix(key, E);
    }

    private static List<Boolean> mix(List<Boolean> lst, int[] idxs) {
        return Arrays.stream(idxs).map(it -> it - 1)
                .mapToObj(lst::get)
                .collect(Collectors.toList());
    }

    private static List<Boolean> shiftRightKey(List<Boolean> key, int iteration) {
        int shiftKey = ITERATION_SHIFT[iteration];
        List<Boolean> C = key.subList(0, key.size() / 2);
        List<Boolean> D = key.subList(key.size() / 2, key.size());

        C = shiftRight(C, shiftKey);
        D = shiftRight(D, shiftKey);

        return Stream.concat(C.stream(), D.stream()).collect(Collectors.toList());
    }

    private static List<Boolean> shiftRight(List<Boolean> bits, int shiftKey) {
        List<Boolean> L = new ArrayList<>(bits.subList(bits.size() - shiftKey, bits.size()));
        L.addAll(bits.subList(0, bits.size() - shiftKey));
        return L;
    }

    private static List<Boolean> shiftLeft(List<Boolean> key, int shiftKey) {
        List<Boolean> R = new ArrayList<>(key.subList(shiftKey, key.size()));
        R.addAll(key.subList(0, shiftKey));
        return R;
    }

    private static List<Boolean> shiftLeftKey(List<Boolean> key, int iteration) {
        int shiftKey = ITERATION_SHIFT[iteration];
        List<Boolean> C = key.subList(0, key.size() / 2);
        List<Boolean> D = key.subList(key.size() / 2, key.size());

        C = shiftLeft(C, shiftKey);
        D = shiftLeft(D, shiftKey);

        return Stream.concat(C.stream(), D.stream()).collect(Collectors.toList());
    }
}
