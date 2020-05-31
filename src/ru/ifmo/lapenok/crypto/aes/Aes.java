package ru.ifmo.lapenok.crypto.aes;

import java.util.ArrayList;
import java.util.List;

public class Aes {
    private static final int nb = 4;//number column of state (aes128)
    private static final int nr = 10; //number of rounds
    private static final int nk = 4; //key length (128 bit)

    private static final int[] sbox = new int[]{
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    private static final int[] inv_sbox = new int[]{
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    private static final int[][] rcon = new int[][]{
            {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    public static void main(String[] args) {
        String input = args[0];
        String key = args[1];
        char[] encoded = encrypt(input.toCharArray(), key);
        System.out.println(new String(encoded));
        System.out.println(new String(decode(encoded, key)));
    }

    public static String encrypt(String input, String key) {
        return new String(encrypt(input.toCharArray(), key));
    }

    private static char[] encrypt(char[] input, String key) {
        List<List<Integer>> state = new ArrayList<>();
        for (int r = 0; r < 4; r++) {
            state.add(new ArrayList<>());
            for (int c = 0; c < nb; c++) {
                state.get(r).add((int) input[r + 4 * c]);
            }
        }

        List<Integer>[] keySchedule = keyExpansion(key);

        state = addRoundKey(state, keySchedule);

        for (int rnd = 1; rnd < nr; rnd++) {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, keySchedule, rnd);
        }

        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, keySchedule, nr);

        char[] output = new char[4 * nb];
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < nb; c++) {
                output[r + 4 * c] = (char) state.get(r).get(c).intValue();
            }
        }
        return output;
    }

    public static String decode(String input, String key) {
        return new String(decode(input.toCharArray(), key));
    }

    private static byte[] decode(char[] input, String key) {
        List<List<Integer>> state = new ArrayList<>();
        for (int r = 0; r < 4; r++) {
            state.add(new ArrayList<>());
            for (int c = 0; c < nb; c++) {
                state.get(r).add((int) input[r + 4 * c]);
            }
        }

        List<Integer>[] keySchedule = keyExpansion(key);

        state = addRoundKey(state, keySchedule, nr);

        for (int rnd = nr - 1; rnd >= 1; rnd--) {
            state = shiftRows(state, true);
            state = subBytes(state, true);
            state = addRoundKey(state, keySchedule, rnd);
            state = mixColumns(state, true);
        }

        state = shiftRows(state, true);
        state = subBytes(state, true);
        state = addRoundKey(state, keySchedule, 0);

        byte[] output = new byte[4 * nb];
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < nb; c++) {
                output[r + 4 * c] = (byte) state.get(r).get(c).intValue();
            }
        }
        return output;
    }

    private static List<Integer>[] keyExpansion(String key) {
        List<Integer> keySymbols = new ArrayList<>();
        for (char symbol : key.toCharArray()) {
            keySymbols.add((int) symbol);
        }

        if (keySymbols.size() < 4 * nk) {
            for (int i = 0; keySymbols.size() < 4 * nk; i++) {
                keySymbols.add(0x01);
            }
        }

        List<Integer>[] keySchedule = new List[4];
        for (int r = 0; r < 4; r++) {
            keySchedule[r] = new ArrayList<>();
            for (int c = 0; c < nk; c++) {
                keySchedule[r].add(keySymbols.get(r + 4 * c));
            }
        }

        for (int col = nk; col < nb * (nr + 1); col++) {
            if (col % nk == 0) {
                List<Integer> tmp = new ArrayList<>();
                for (int row = 0; row < 4; row++) {
                    tmp.add(keySchedule[row].get(col - 1));
                }
                tmp.add(keySchedule[0].get(col - 1));

                for (int j = 0; j < tmp.size(); j++) {
                    int sbox_row = tmp.get(j) / 0x10;
                    int sbox_col = tmp.get(j) % 0x10;
                    int sbox_elem = sbox[16 * sbox_row + sbox_col];
                    tmp.set(j, sbox_elem);
                }

                for (int row = 0; row < 4; row++) {
                    int s = (keySchedule[row].get(col - 4)) ^ (tmp.get(row) ^ rcon[row][col / nk - 1]);
                    keySchedule[row].add(s);
                }
            } else {
                for (int row = 0; row < 4; row++) {
                    int s = keySchedule[row].get(col - 4) ^ keySchedule[row].get(col - 1);
                    keySchedule[row].add(s);
                }
            }
        }
        return keySchedule;
    }

    private static List<List<Integer>> addRoundKey(List<List<Integer>> state, List<Integer>[] keySchedule) {
        return addRoundKey(state, keySchedule, 0);
    }

    private static List<List<Integer>> addRoundKey(List<List<Integer>> state, List<Integer>[] keySchedule, int round) {
        for (int col = 0; col < nk; col++) {
            int s0 = state.get(0).get(col) ^ keySchedule[0].get(nb * round + col);
            int s1 = state.get(1).get(col) ^ keySchedule[1].get(nb * round + col);
            int s2 = state.get(2).get(col) ^ keySchedule[2].get(nb * round + col);
            int s3 = state.get(3).get(col) ^ keySchedule[3].get(nb * round + col);

            state.get(0).set(col, s0);
            state.get(1).set(col, s1);
            state.get(2).set(col, s2);
            state.get(3).set(col, s3);
        }
        return state;
    }

    private static List<List<Integer>> subBytes(List<List<Integer>> state) {
        return subBytes(state, false);
    }

    private static List<List<Integer>> subBytes(List<List<Integer>> state, boolean inv) {
        final int[] box;
        if (inv) {//decrypt
            box = inv_sbox;
        } else {//encrypt
            box = sbox;
        }

        for (int i = 0; i < state.size(); i++) {
            for (int j = 0; j < state.get(i).size(); j++) {
                int row = state.get(i).get(j) / 0x10;
                int col = state.get(i).get(j) % 0x10;

                if (16*row+col<0) {
                    System.out.println(""+row+""+col);
                }

                int boxElem = box[16 * row + col];
                state.get(i).set(j, boxElem);
            }
        }
        return state;
    }

    private static List<List<Integer>> shiftRows(List<List<Integer>> state) {
        return shiftRows(state, false);
    }

    private static List<List<Integer>> shiftRows(List<List<Integer>> state, boolean inv) {
        int count = 1;
        if (inv) {//decrypt
            for (int i = 1; i < nb; i++) {
                state.set(i, rightShift(state.get(i), count));
                count++;
            }
        } else {
            for (int i = 1; i < nb; i++) {
                state.set(i, leftShift(state.get(i), count));
                count++;
            }
        }
        return state;
    }

    private static List<Integer> rightShift(List<Integer> array, int count) {
        List<Integer> result = new ArrayList<>(array.subList(array.size() - count, array.size()));
        result.addAll(array.subList(0, array.size() - count));
        return result;
    }

    private static List<Integer> leftShift(List<Integer> key, int count) {
        List<Integer> result = new ArrayList<>(key.subList(count, key.size()));
        result.addAll(key.subList(0, count));
        return result;
    }

    private static List<List<Integer>> mixColumns(List<List<Integer>> state) {
        return mixColumns(state, false);
    }

    private static List<List<Integer>> mixColumns(List<List<Integer>> state, boolean inv) {
        for (int i = 0; i < nb; i++) {
            int s0, s1, s2, s3;
            if (inv) {
                s0 = mul_by_0e(state.get(0).get(i)) ^ mul_by_0b(state.get(1).get(i)) ^ mul_by_0d(state.get(2).get(i)) ^ mul_by_09(state.get(3).get(i));
                s1 = mul_by_09(state.get(0).get(i)) ^ mul_by_0e(state.get(1).get(i)) ^ mul_by_0b(state.get(2).get(i)) ^ mul_by_0d(state.get(3).get(i));
                s2 = mul_by_0d(state.get(0).get(i)) ^ mul_by_09(state.get(1).get(i)) ^ mul_by_0e(state.get(2).get(i)) ^ mul_by_0b(state.get(3).get(i));
                s3 = mul_by_0b(state.get(0).get(i)) ^ mul_by_0d(state.get(1).get(i)) ^ mul_by_09(state.get(2).get(i)) ^ mul_by_0e(state.get(3).get(i));
            } else {
                s0 = mul_by_02(state.get(0).get(i)) ^ mul_by_03(state.get(1).get(i)) ^ state.get(2).get(i) ^ state.get(3).get(i);
                s1 = state.get(0).get(i) ^ mul_by_02(state.get(1).get(i)) ^ mul_by_03(state.get(2).get(i)) ^ state.get(3).get(i);
                s2 = state.get(0).get(i) ^ state.get(1).get(i) ^ mul_by_02(state.get(2).get(i)) ^ mul_by_03(state.get(3).get(i));
                s3 = mul_by_03(state.get(0).get(i)) ^ state.get(1).get(i) ^ state.get(2).get(i) ^ mul_by_02(state.get(3).get(i));
            }

            state.get(0).set(i, s0);
            state.get(1).set(i, s1);
            state.get(2).set(i, s2);
            state.get(3).set(i, s3);
        }
        return state;
    }

    private static int mul_by_02(int num) {
        int res;
        if (num < 0x80)
            res = (num << 1);
        else
            res = (num << 1) ^ 0x1b;

        return res % 0x100;
    }


    private static int mul_by_03(int num) {
        return (mul_by_02(num) ^ num);
    }


    private static int mul_by_09(int num) {
        return mul_by_02(mul_by_02(mul_by_02(num))) ^ num;
    }


    private static int mul_by_0b(int num) {
        return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num;
    }


    private static int mul_by_0d(int num) {
        return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num;
    }


    private static int mul_by_0e(int num) {
        return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ mul_by_02(num);
    }
}
