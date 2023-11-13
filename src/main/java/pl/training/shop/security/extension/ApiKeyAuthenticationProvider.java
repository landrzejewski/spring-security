package pl.training.shop.security.extension;

import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private static final Set<GrantedAuthority> DEFAULT_ROLES = Set.of("ROLE_ADMIN")
            .stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());

    @Value("${api-key}")
    @Setter
    private String apiKey;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof ApiKeyAuthentication apiKeyAuthentication) {
            var key = apiKeyAuthentication.getKey();
            if (this.apiKey.equals(key)) {
                return new ApiKeyAuthentication("", DEFAULT_ROLES, true);
            } else {
                throw new BadCredentialsException("Invalid api key");
            }
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthentication.class.isAssignableFrom(authentication);
    }

}
