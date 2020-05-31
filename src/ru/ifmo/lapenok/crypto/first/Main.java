package ru.ifmo.lapenok.crypto.first;

import javafx.util.Pair;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Main {
    private static final List<Character> characters = new ArrayList<>();

    static {
        for (char a = 'а'; a < 'я'; a++) {
            characters.add(a);
        }
    }

    private static final Map<Character, Integer> charToInt = IntStream.range(0, characters.size()).boxed()
            .collect(Collectors.toMap(characters::get, Function.identity()));

    private static int digramLength = 3;

    public static void main(String[] args) {
        final String encodedText = encode(args[0], args[1]);
        System.out.println(encodedText);
        System.out.println(decode(encodedText, args[1]));
        System.out.println(hack(encodedText));
    }

    private static String encode(String text, String key) {
        final StringBuilder output = new StringBuilder(text.length());
        text = text.toLowerCase();
        key = key.toLowerCase();
        int j = 0;
        for (int i = 0; i < text.length(); i++) {
            if (!charToInt.containsKey(text.charAt(i))) {
                output.append(text.charAt(i));
            } else {
                int textCh = charToInt.get(text.charAt(i));
                int keyCh = charToInt.get(key.charAt(j % key.length()));
                j++;

                int resultCh = (textCh + keyCh) % characters.size();
                output.append(characters.get(resultCh));
            }
        }
        return output.toString();
    }

    private static String decode(String text, String key) {
        final StringBuilder output = new StringBuilder(text.length());
        text = text.toLowerCase();
        key = key.toLowerCase();
        int j = 0;
        for (int i = 0; i < text.length(); i++) {
            if (!charToInt.containsKey(text.charAt(i))) {
                output.append(text.charAt(i));
            } else {
                int textCh = charToInt.get(text.charAt(i));
                int keyCh = charToInt.get(key.charAt(j % key.length()));
                j++;

                int resultCh = textCh - keyCh;
                if (resultCh < 0) {
                    resultCh += characters.size();
                }
                output.append(characters.get(resultCh));
            }
        }
        return output.toString();
    }

    private static String hack(String text) {
        final List<Integer> repeatCount = new ArrayList<>();
        for (int i = 0; i < text.length() - digramLength + 1; i++) {
            final String temp = text.substring(i, i + digramLength);
            for (int j = i + 1; j < text.length() - digramLength + 1; j++) {
                final String temp2 = text.substring(j, j + digramLength);
                if (temp.equals(temp2)) {
                    repeatCount.add(j - i);
                }
            }
        }

        int[] nods = new int[5000];
        for (int i = 0; i < repeatCount.size(); i++) {
            for (int j = i + 1; j < repeatCount.size(); j++) {
                nods[(int)gcd(repeatCount.get(i), repeatCount.get(j))]++;
            }
        }
        nods[0] = 0;

        final List<Pair<Integer, Integer>> ans = new ArrayList<>();
        for (int i = 2; i < 500; i++) {
            ans.add(new Pair<>(i, nods[i]));
        }
        List<Pair<Integer, Integer>> anss = ans.stream().sorted(Comparator.<Pair<Integer, Integer>>comparingInt(Pair::getValue).reversed()).limit(10).collect(Collectors.toList());

        final StringBuilder stringAns = new StringBuilder();
        for (Pair<Integer, Integer> s : anss) {
            if (s.getValue() > 0) {
                stringAns.append(s.getKey()).append(":").append(s.getValue()).append(" ");
            }
        }
        System.out.println(stringAns);

        return stringAns.toString();
    }

    public static long gcd(long a, long b) {
        if (b == 0)
            return a;
        return gcd(b, a % b);
    }
}
