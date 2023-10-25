package pl.training.shop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.oauth2ResourceServer(config -> config
                        /*.jwt(jwtConfig -> jwtConfig
                                .jwkSetUri("http://localhost:8090/oauth2/jwks")
                                .jwtAuthenticationConverter(new CustomJwtAuthenticationConverter())
                        )*/
                        .opaqueToken(
                                opaqueTokenConfig -> opaqueTokenConfig
                                        .introspectionUri("http://localhost:8090/oauth2/introspect")
                                        .introspectionClientCredentials("resource_server", "resource_server_secret")
                        )
                )
                .authorizeHttpRequests(config -> config
                        .anyRequest().hasRole("ADMIN")
                )
                .build();
    }


}
