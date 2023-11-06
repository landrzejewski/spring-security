package pl.training.shop.security.extensions;

import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecretAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;

    @Value("${secret}")
    @Setter
    private String secret;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof SecretAuthentication secretAuthentication) {
            var secret = secretAuthentication.getSecret();
            if (passwordEncoder.matches(new String(secret), this.secret)) {
                var user = User.withUsername("system")
                        .password("system")
                        .roles("ADMIN")
                        .build();
                var authenticationResult = UsernamePasswordAuthenticationToken
                        .authenticated(user, secret, user.getAuthorities());
                authenticationResult.setDetails(user);
                return authenticationResult;
            } else {
                throw new BadCredentialsException("Invalid secret");
            }
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(SecretAuthentication.class);
    }
}
