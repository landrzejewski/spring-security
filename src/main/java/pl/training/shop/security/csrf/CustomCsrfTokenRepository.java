package pl.training.shop.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
public class CustomCsrfTokenRepository implements CsrfTokenRepository {

    private final JpaTokenRepository jpaTokenRepository;

    public CustomCsrfTokenRepository(JpaTokenRepository jpaTokenRepository) {
        this.jpaTokenRepository = jpaTokenRepository;
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest httpServletRequest) {
        String uuid = UUID.randomUUID().toString();
        return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", uuid);
    }

    @Override
    public void saveToken(CsrfToken csrfToken,
                          HttpServletRequest httpServletRequest,
                          HttpServletResponse httpServletResponse) {
        String identifier = httpServletRequest.getSession().getId();
        Optional<TokenEntity> existingToken = jpaTokenRepository.findTokenByIdentifier(identifier);

        if (existingToken.isPresent()) {
            TokenEntity tokenEntity = existingToken.get();
            tokenEntity.setToken(csrfToken.getToken());
        } else {
            TokenEntity tokenEntity = new TokenEntity();
            tokenEntity.setToken(csrfToken.getToken());
            tokenEntity.setIdentifier(identifier);
            jpaTokenRepository.save(tokenEntity);
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest httpServletRequest) {
        String identifier = httpServletRequest.getSession().getId();
        Optional<TokenEntity> existingToken = jpaTokenRepository.findTokenByIdentifier(identifier);

        if (existingToken.isPresent()) {
            TokenEntity tokenEntity = existingToken.get();
            return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", tokenEntity.getToken());
        }

        return null;
    }

    public void test() {
        // Spring Security Crypto module
        var keyGenerator = KeyGenerators.string();
        var salt = keyGenerator.generateKey();

        var keyGenerator2 = KeyGenerators.secureRandom(16);
        byte[] key = keyGenerator2.generateKey();
        int keyLength = keyGenerator2.getKeyLength();

        var keyGenerator3 = KeyGenerators.shared(16);
        byte[] key1 = keyGenerator3.generateKey();
        byte[] key2 = keyGenerator3.generateKey();

        String valueToEncrypt = "HELLO";
        var encryptor = Encryptors.standard("secret", KeyGenerators.string().generateKey()); //  256-byte AES
        // = Encryptors.stronger(password, salt);
        byte[] encrypted = encryptor.encrypt(valueToEncrypt.getBytes());
        byte[] decrypted = encryptor.decrypt(encrypted);


        var textEncryptor = Encryptors.text("secret", KeyGenerators.string().generateKey());
        String encrypted2 = textEncryptor.encrypt(valueToEncrypt);
        String decrypted2 = textEncryptor.decrypt(encrypted2);
    }

}
