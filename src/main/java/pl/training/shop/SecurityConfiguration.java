package pl.training.shop;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfiguration {

    private static final String REALM_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService() {
        var user = User
                .withUsername("admin@training.pl")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN")
                .build();
        return new MapReactiveUserDetailsService(user);
    }

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity httpSecurity) {
        return httpSecurity
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/me").hasRole("ADMIN")
                        .anyExchange().hasRole("ADMIN")
                )
                .httpBasic(withDefaults())
                .oauth2Login(withDefaults())
                .oauth2ResourceServer(config -> config
                        .jwt(this::jwtConfigurer)
                )
                .build();
    }

    private void jwtConfigurer(JwtSpec jwtspec) {
        var jwtConverter = new ReactiveJwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtGrantedAuthoritiesConverter());
        jwtspec.jwtAuthenticationConverter(jwtConverter);
    }

    @Bean
    public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        var oidcReactiveOAuth2UserService = new OidcReactiveOAuth2UserService();
        var keycloakGrantedAuthoritiesMapper = new KeycloakGrantedAuthoritiesMapper();
        return userRequest -> oidcReactiveOAuth2UserService
                .loadUser(userRequest)
                .map(oidcUser -> new DefaultOidcUser(keycloakGrantedAuthoritiesMapper.mapAuthorities(oidcUser.getAuthorities()), oidcUser.getIdToken(), oidcUser.getUserInfo()));
    }

}
