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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import pl.training.shop.security.extensions.CustomEntryPoint;
import pl.training.shop.security.extensions.SecretAuthenticationProvider;
import pl.training.shop.security.extensions.SecurityLoggingFilter;
import pl.training.shop.security.extensions.jwt.JwtAuthenticationFilter;
import pl.training.shop.security.extensions.jwt.JwtAuthenticationProvider;

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

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, SecurityLoggingFilter securityLoggingFilter,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        return httpSecurity
                //.addFilterBefore(secretAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(securityLoggingFilter, ExceptionTranslationFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                //.anonymous(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
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
                        .requestMatchers("/api/payments/{id:^\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}$}")
                            //.hasAnyRole("ADMIN", "MANAGER")
                            //.hasAuthority("read")
                            .hasRole("ADMIN")
                        .requestMatchers("/**").authenticated()

                        //.anyRequest().access(new WebExpressionAuthorizationManager("hasAuthority('WRITE')"))
                        //.requestMatchers("/**").access((authentication, object) -> new AuthorizationDecision(true))
                        //.requestMatchers("/**").access(customAuthorizationManager)
                        .anyRequest().authenticated()
                )
                /*.exceptionHandling(config -> config
                        //.authenticationEntryPoint(implementacja AuthenticationEntryPoint)
                        //.accessDeniedHandler(implementacja AccessDeniedHandler)
                        //.accessDeniedPage("/access-denied.html")
                )*/
                .build();
    }

}
