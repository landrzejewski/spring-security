package pl.training.shop.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.stream.Collectors;

public class CustomJwtAuthenticationConverter implements Converter<Jwt, CustomJwtAuthentication> {

    @Override
    public CustomJwtAuthentication convert(Jwt jwt) {
        var authorities = jwt.getClaimAsStringList("authorities").stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        var zone = jwt.getClaimAsString("zone");
        return new CustomJwtAuthentication(jwt, authorities, zone);
    }

}
