package pl.training.shop.security;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Optional;

public class Token {

    public static final String PREFIX = "bearer ";

    public static Optional<String> getValue() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken authenticationToken) {
            return Optional.of(authenticationToken)
                    .map(JwtAuthenticationToken::getToken)
                    .map(Jwt::getTokenValue);
        } else {
            return Optional.empty();
        }
    }

    public static Optional<String> getAuthorizationHeaderValue() {
        return getValue().map(token -> PREFIX + token);
    }

}
