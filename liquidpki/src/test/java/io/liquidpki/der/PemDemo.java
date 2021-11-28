package io.liquidpki.der;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.stream.Collectors;

public class PemDemo {

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Call with filenames you want to decode");
            System.exit(0);
        }
        for (String arg : args) {
            System.out.println(arg);
            decodePemFile(arg).output(System.out, "");
        }
   }

    private static Der decodePemFile(String filename) throws IOException {
        String pemContent = Files.readAllLines(Paths.get(filename)).stream()
                .filter(s -> !s.startsWith("-----"))
                .map(String::trim)
                .collect(Collectors.joining(""));
        return Der.parse(Base64.getDecoder().decode(pemContent));
    }
}
