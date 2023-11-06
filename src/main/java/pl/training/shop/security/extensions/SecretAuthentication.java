package pl.training.shop.security.extensions;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import static java.util.Collections.emptyList;

public class SecretAuthentication extends AbstractAuthenticationToken {

    @Getter
    private final char[] secret;

    public SecretAuthentication(char[] secret) {
        super(emptyList());
        this.secret = secret;
    }

    @Override
    public Object getCredentials() {
        return secret;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

}
