package pl.training.shop.security.extensions.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.stream.Collectors;

import static pl.training.shop.security.extensions.jwt.JwtConfig.*;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    private static final String ROLE_SEPARATOR = ",";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof JwtAuthentication jwtAuthentication) {
            var token = jwtAuthentication.getToken();
            try {
                var verifier = JWT.require(ALGORITHM)
                        .withIssuer(ISSUER)
                        .build();
                var decodedJwt = verifier.verify(token);
                var user = decodedJwt.getClaim(USER_CLAIM).asString();
                var roles = decodedJwt.getClaim(ROLES_CLAIM).asString();
                var authorities = Arrays.stream(roles.split(ROLE_SEPARATOR))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toSet());
                return UsernamePasswordAuthenticationToken.authenticated(user, token, authorities);
            } catch (JWTVerificationException jwtVerificationException) {
                throw new BadCredentialsException("Invalid token");
            }
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }

}
