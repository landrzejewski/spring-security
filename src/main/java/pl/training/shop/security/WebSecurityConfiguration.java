package pl.training.shop.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import pl.training.shop.security.extension.ApiKeyAuthenticationFilter;
import pl.training.shop.security.extension.CustomEntryPoint;
import pl.training.shop.security.users.JpaUserDetailsServiceAdapter;

@EnableWebSecurity(debug = true)
@Configuration
public class WebSecurityConfiguration {

    // Opcjonalnie - providers są rejestrowani automatycznie jeśli są skonfigurowane jako beany
    /*@Autowired
    public void configure(AuthenticationManagerBuilder builder, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        var daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);

        builder.authenticationProvider(daoAuthenticationProvider);
        builder.authenticationProvider(new ApiKeyAuthenticationProvider());
    }*/

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   ApiKeyAuthenticationFilter apiKeyAuthenticationFilter
                                                   /*JpaUserDetailsServiceAdapter userDetailsService*/) throws Exception {
        return httpSecurity
                .addFilterAfter(apiKeyAuthenticationFilter, BasicAuthenticationFilter.class)
                //.userDetailsService(userDetailsService)
                .authorizeHttpRequests(config -> config
                                .requestMatchers("/api/tokens").permitAll()
                                .requestMatchers("/login.html").permitAll()
                                .requestMatchers("/favicon.ico").permitAll()
                                //.requestMatchers("/api/payments/{id:^\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}$}")
                                    //.hasAnyRole("ADMIN", "MANAGER")
                                    //.hasAuthority("read")
                                    //.hasRole("ADMIN")
                                .requestMatchers("/**").hasRole("ADMIN")
                                //.anyRequest().access(new WebExpressionAuthorizationManager("hasAuthority('WRITE')"))
                                //.anyRequest().access((authentication, object) -> new AuthorizationDecision(true))
                                //.anyRequest().access(customAuthorizationManager)
                                //.anyRequest().authenticated()
                )
                //.httpBasic(withDefaults())
                .httpBasic(config -> config
                        .realmName("TRAINING")
                        .authenticationEntryPoint(new CustomEntryPoint())
                )
                .formLogin(config -> config
                                .loginPage("/login.html")
                                .defaultSuccessUrl("/index.html")
                                //.usernameParameter("username")
                                //.passwordParameter("password")
                                //.successHandler(implementacja AuthenticationSuccessHandler)
                                //.failureHandler(implementacja AuthenticationFailureHandler)
                )
                .logout(config -> config
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout.html")) // default /logout
                        .invalidateHttpSession(true)
                        .logoutSuccessUrl("/login.html")
                )
                .build();
    }

}
