package pl.training.authorizationserver;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class GenerateChallenge {

    public static void main(String[] args) {
        String verifier = "A-9NJaJ2t18dQ8WAV6Hu3e3sd9rDk7icGEnATsIsLKM";
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
