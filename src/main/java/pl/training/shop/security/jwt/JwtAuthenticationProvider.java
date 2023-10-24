package pl.training.shop.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Set;

import static pl.training.shop.security.jwt.JwtConfig.*;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

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
                var role = decodedJwt.getClaim(ROLE_CLAIM).asString();
                return UsernamePasswordAuthenticationToken
                        .authenticated(user, token, Set.of(new SimpleGrantedAuthority(role)));
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
