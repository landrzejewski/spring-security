package pl.training.shop.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import pl.training.shop.security.extensions.CustomAuthorizationManager;
import pl.training.shop.security.extensions.CustomEntryPoint;
import pl.training.shop.security.extensions.SecretAuthenticationProvider;
import pl.training.shop.security.extensions.SecurityLoggingFilter;
import pl.training.shop.security.extensions.csrf.CustomCsrfTokenRepository;
import pl.training.shop.security.extensions.jwt.JwtAuthenticationFilter;
import pl.training.shop.security.extensions.jwt.JwtAuthenticationProvider;

import java.util.Arrays;
import java.util.List;

@Configuration
public class WebSecurityConfiguration {

    // Wymagane tylko, gdy potrzebujemy wielu obiektów AuthenticationProvider
    @Autowired
    public void configure(AuthenticationManagerBuilder builder, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        var daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);

        builder.authenticationProvider(daoAuthenticationProvider);
        builder.authenticationProvider(new JwtAuthenticationProvider());
        builder.authenticationProvider(new SecretAuthenticationProvider(passwordEncoder));
    }

    private CorsConfigurationSource corsConfigurationSource() {
        var configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("https://example.com"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, SecurityLoggingFilter securityLoggingFilter,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   CustomCsrfTokenRepository csrfTokenRepository,
                                                   CustomAuthorizationManager customAuthorizationManager) throws Exception {
        return httpSecurity
                //.addFilterBefore(secretAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(securityLoggingFilter, ExceptionTranslationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                //.anonymous(AbstractHttpConfigurer::disable)
                //.csrf(config -> config.disable()) // CSRF (Cross-Site Request Forgery)
                .csrf(config -> {
                            /*var i = new HandlerMappingIntrospector();
                            var r = new MvcRequestMatcher(i, "/test");
                            config.ignoringRequestMatchers(r);*/

                            /*var r = new RegexRequestMatcher(".*[0-9].*", "POST");
                            config.ignoringRequestMatchers(r);*/

                            config.ignoringRequestMatchers("/api/**");

                            // CsrfToken — Describes the CSRF token itself
                            // CsrfTokenRepository — Describes the object that creates, stores, and loads CSRF  tokens
                            // CsrfTokenRequestHandler – Describes and object that manages the way in which the  generated CSRF token is set on the HTTP request.

                            config.csrfTokenRepository(csrfTokenRepository);
                            config.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()); // XorCsrfTokenRequestAttributeHandler
                        }
                )
                .cors(config -> config.configurationSource(corsConfigurationSource()))
                //.userDetailsService(implementacja UserDetailsService)
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
                        //.failureHandler(implementacja CustomAuthenticationFailureHandler)
                )
                .logout(config -> config
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout.html"))
                        .invalidateHttpSession(true)
                        .logoutSuccessUrl("/login.html")
                )
                .authorizeHttpRequests(config -> config
                        .requestMatchers("/api/tokens").permitAll()
                        .requestMatchers("/login.html").permitAll()
                        .requestMatchers("/favicon.ico").permitAll()
                        //.requestMatchers("/api/payments/{id:^\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}$}")
                            //.hasAnyRole("ADMIN", "MANAGER")
                            //.hasAuthority("read")
                            //.hasRole("ADMIN")
                        //.requestMatchers("/**").authenticated()
                        //.anyRequest().access(new WebExpressionAuthorizationManager("hasAuthority('WRITE')"))
                        //.anyRequest().access((authentication, object) -> new AuthorizationDecision(true))
                        //.anyRequest().access(customAuthorizationManager)
                        //.anyRequest().authenticated()
                        .anyRequest().access(customAuthorizationManager)
                )
                /*.exceptionHandling(config -> config
                        //.authenticationEntryPoint(implementacja AuthenticationEntryPoint)
                        //.accessDeniedHandler(implementacja AccessDeniedHandler)
                        //.accessDeniedPage("/access-denied.html")
                )*/
                .build();
    }

}
