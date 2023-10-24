package pl.training.shop.security.extensions;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private static final String EMPTY = "";

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof PlainAuthentication plainAuthentication) {
            var username = plainAuthentication.getLogin();
            var password = plainAuthentication.getPassword();
            var user = userDetailsService.loadUserByUsername(username);
            if (passwordEncoder.matches(password, user.getPassword())) {
                var token = UsernamePasswordAuthenticationToken.authenticated(user, EMPTY, user.getAuthorities());
                token.setDetails(user);
                return token;
            } else {
                throw new BadCredentialsException("Invalid username or password");
            }
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PlainAuthentication.class.isAssignableFrom(authentication);
    }

}
