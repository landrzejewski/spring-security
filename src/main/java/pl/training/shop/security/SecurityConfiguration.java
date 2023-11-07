package pl.training.shop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

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
                .authorizeHttpRequests(config -> config
                        .anyRequest().hasRole("ADMIN")
                )
                .build();
    }

    private void jwtConfigurer(OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer jwtConfigurer) {
        var jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter();
        jwtConfigurer.jwtAuthenticationConverter(jwtConverter);
    }

}
