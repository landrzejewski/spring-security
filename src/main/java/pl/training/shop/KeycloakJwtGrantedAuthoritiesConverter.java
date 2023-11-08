package pl.training.shop;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import reactor.core.publisher.Flux;

public class KeycloakJwtGrantedAuthoritiesConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

    private static final String REALM_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    @Nullable
    public Flux<GrantedAuthority> convert(Jwt source) {
        Map<String, List<String>> realm = source.getClaim(REALM_CLAIM);
        return Flux.fromStream(realm.get(ROLES_CLAIM).stream()
                .map(role -> ROLE_PREFIX + role)
                .map(SimpleGrantedAuthority::new)
                );
    }


}
