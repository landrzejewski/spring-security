package pl.training.authorizationserver;

import java.security.SecureRandom;
import java.util.Base64;

public class GenerateVerifier {

    public static void main(String[] args) {
        System.out.println(generateVerifier());
    }

    public static String generateVerifier() {
        var secureRandom = new SecureRandom();
        var code = new byte[32];
        secureRandom.nextBytes(code);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(code);
    }

}
