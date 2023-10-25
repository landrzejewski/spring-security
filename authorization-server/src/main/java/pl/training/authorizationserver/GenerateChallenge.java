package pl.training.authorizationserver;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class GenerateChallenge {

    public static void main(String[] args) {
        String verifier = "H05Q8TLWkVz2_uVbgXy8J9LlezXzE2FyCE_rwE4t7h0";
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
