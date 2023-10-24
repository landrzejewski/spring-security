package pl.training.shop.security.csrf;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
}
