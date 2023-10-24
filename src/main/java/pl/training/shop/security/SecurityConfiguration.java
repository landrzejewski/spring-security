package pl.training.shop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer.UserInfoEndpointConfig;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfiguration {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(config -> config
                        .ignoringRequestMatchers("/api/**")
                )
                .oauth2Login(config ->
                        config.userInfoEndpoint(this::oauth2LoginConfig)
                )
                .oauth2ResourceServer(config -> config
                        .jwt(this::jwtConfig)
                )
                .authorizeHttpRequests(config -> config
                        .anyRequest().hasRole("ADMIN")
                )
                .build();
    }

    private void jwtConfig(OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
        var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtGrantedAuthoritiesConverter());
        jwtConfigurer.jwtAuthenticationConverter(converter);
    }

    private static final String REALM_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    // Client scopes -> Client scope details -> Mapper details -> Add to userinfo enabled (Keycloak Admin console)
    @SuppressWarnings("unchecked")
    private void oauth2LoginConfig(UserInfoEndpointConfig config) {
        config.userAuthoritiesMapper(authorities -> {
            Set<String> grantedAuthorities = new HashSet<>();
            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                    var userInfo = oidcUserAuthority.getUserInfo();
                    var realmAccess = userInfo.getClaimAsMap(REALM_CLAIM);
                    var roles = (Collection<String>) realmAccess.get(ROLES_CLAIM);
                    grantedAuthorities.addAll(roles);
                } else if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {
                    var userAttributes = oauth2UserAuthority.getAttributes();
                    var realmAccess = (Map<String, Object>) userAttributes.get(REALM_CLAIM);
                    var roles = (Collection<String>) realmAccess.get(ROLES_CLAIM);
                    grantedAuthorities.addAll(roles);
                } else {
                    grantedAuthorities.add(authority.getAuthority());
                }
            });
            return grantedAuthorities.stream()
                    .map(role -> ROLE_PREFIX + role)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
        });
    }

}
