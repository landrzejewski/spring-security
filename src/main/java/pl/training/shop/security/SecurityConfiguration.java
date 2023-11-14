package pl.training.shop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;

import static org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(config -> config
                        .ignoringRequestMatchers("/api/**")
                )
                .oauth2ResourceServer(config -> config
                        .jwt(this::jwtConfigurer)
                )
                .oauth2Login(config -> config.userInfoEndpoint(this::userInfoCustomizer))
                .logout(config -> config
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout.html"))
                        .addLogoutHandler(new KeycloakLogoutHandler(new RestTemplate()))
                        .logoutSuccessUrl("/index.html")
                )
                .sessionManagement(config -> config
                        .sessionCreationPolicy(IF_REQUIRED)
                )
                .authorizeHttpRequests(config -> config
                        .anyRequest().authenticated()
                )
                .build();
    }

    // Client scopes -> Client scope details (roles) -> Mapper details -> Add to userinfo enabled (Keycloak Admin console)
    private void userInfoCustomizer(OAuth2LoginConfigurer.UserInfoEndpointConfig userInfoEndpointConfig) {
        userInfoEndpointConfig.userAuthoritiesMapper(new KeycloakGrantedAuthoritiesMapper());
    }

    private void jwtConfigurer(OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer) {
        var jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtGrantedAuthoritiesConverter());
        jwtConfigurer.jwtAuthenticationConverter(jwtConverter);
    }

}
