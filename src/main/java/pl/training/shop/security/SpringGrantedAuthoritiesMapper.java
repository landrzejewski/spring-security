package pl.training.shop.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.stream.Collectors;

public class SpringGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

    private static final String ROLES_CLAIM = "authorities";
    private static final String ROLE_PREFIX = "ROLE_";

    @SuppressWarnings("unchecked")
    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        var grantedAuthorities = new HashSet<String>();
        authorities.forEach(authority -> {
            if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {
                var userAttributes = oauth2UserAuthority.getAttributes();
                var roles = (Collection<String>) userAttributes.get(ROLES_CLAIM);
                grantedAuthorities.addAll(roles);
            } else {
                grantedAuthorities.add(authority.getAuthority());
            }
        });
        return grantedAuthorities.stream()
                .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

}
