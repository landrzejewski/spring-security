package pl.training.shop;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.HashSet;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec.JwtSpec;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;

import reactor.core.publisher.Mono;

@EnableReactiveMethodSecurity
//@EnableWebFluxSecurity
@Configuration
public class SecurityConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService() {
        var user = User.withUsername("admin@training.pl")
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
                .formLogin(withDefaults())
                .oauth2Login(withDefaults())
                .oauth2ResourceServer(config -> config
                        .jwt(this::jwtConfigurer)
                )
                .build();
    }

    private Mono<AuthorizationDecision> authorize(Mono<Authentication> authenticationMono, AuthorizationContext context) {
        var path = context.getExchange().getRequest().getPath();
        var authoritiesMono = authenticationMono.map(Authentication::getAuthorities);
        return Mono.just(new AuthorizationDecision(true));
    }

    private void jwtConfigurer(JwtSpec jwtspec) {
        var jwtConverter = new ReactiveJwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtGrantedAuthoritiesConverter());
        jwtspec.jwtAuthenticationConverter(jwtConverter);
    }

    @Bean
	public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();

		return (userRequest) -> {
			// Delegate to the default implementation for loading a user
			return delegate.loadUser(userRequest)
					.flatMap((oidcUser) -> {
						OAuth2AccessToken accessToken = userRequest.getAccessToken();
						Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

						// TODO
						// 1) Fetch the authority information from the protected resource using accessToken
						// 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities

						// 3) Create a copy of oidcUser but use the mappedAuthorities instead
						oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

						return Mono.just(oidcUser);
					});
		};
    }
}
