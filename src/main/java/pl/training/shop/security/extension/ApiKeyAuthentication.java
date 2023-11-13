package pl.training.shop.security.extension;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

import static java.util.Collections.emptyList;

public class ApiKeyAuthentication extends AbstractAuthenticationToken {

    @Getter
    private final String key;

    public ApiKeyAuthentication(String key) {
        this(key, emptyList(), false);
    }

    public ApiKeyAuthentication(String key, Collection<GrantedAuthority> authorities, boolean isAuthenticated) {
        super(authorities);
        this.key = key;
        this.setAuthenticated(isAuthenticated);
    }

    @Override
    public Object getCredentials() {
        return key;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

}
