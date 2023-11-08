package pl.training.authorizationserver;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class GenerateChallenge {

    public static void main(String[] args) {
        String verifier = "mT-CWdklcpEjH-jiSF-Akvo2AwXpb-kNaJld-PWIDlw";
        System.out.println(generateChallenge(verifier));
    }

    public static String generateChallenge(String verifier) {
        try {
            var messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digested = messageDigest.digest(verifier.getBytes());
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(digested);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
