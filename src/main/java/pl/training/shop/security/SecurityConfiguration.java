package pl.training.shop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .oauth2ResourceServer(config -> config
                        .jwt(this::jwtConfigurer)
                        /*.opaqueToken(opaqueTokenConfig -> opaqueTokenConfig
                                .introspectionUri("http://localhost:8090/oauth2/introspect")
                                .introspectionClientCredentials("payments_resource_server", passwordEncoder().encode("secret"))
                        )*/
                )
                .oauth2Login(config ->
                        config.userInfoEndpoint(this::oauth2LoginConfig)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(config -> config
                        .anyRequest().hasRole("ADMIN")
                )
                .build();
    }

    private void jwtConfigurer(OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
        var jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(new SpringJwtGrantedAuthoritiesConverter());
        jwtConfigurer.jwtAuthenticationConverter(jwtConverter);
        jwtConfigurer.jwkSetUri("http://localhost:8090/oauth2/jwks");
    }

    private void oauth2LoginConfig(OAuth2LoginConfigurer.UserInfoEndpointConfig config) {
        config.userAuthoritiesMapper(new SpringGrantedAuthoritiesMapper());
    }

}
