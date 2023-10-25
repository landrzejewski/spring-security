package pl.training.shop.security;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;

public class CustomJwtAuthentication extends JwtAuthenticationToken {

    @Getter
    private final String zone;

    public CustomJwtAuthentication(Jwt jwt, Collection<? extends GrantedAuthority> authorities, String zone) {
        super(jwt, authorities);
        this.zone = zone;
    }

}
