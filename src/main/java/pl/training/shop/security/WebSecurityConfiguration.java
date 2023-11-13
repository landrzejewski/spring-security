package pl.training.shop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pl.training.shop.security.extension.ApiKeyAuthenticationFilter;

@Configuration
public class WebSecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, ApiKeyAuthenticationFilter apiKeyAuthenticationFilter) throws Exception {
        return httpSecurity
                .addFilterBefore(apiKeyAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(config -> config
                        .anyRequest().authenticated()
                )
                .build();
    }

}
