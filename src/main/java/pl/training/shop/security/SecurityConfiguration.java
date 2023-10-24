package pl.training.shop.security;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import pl.training.shop.security.csrf.CustomCsrfTokenRepository;
import pl.training.shop.security.users.JpaUserDetailService;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.core.context.SecurityContextHolder.MODE_INHERITABLETHREADLOCAL;

//@EnableWebSecurity(debug = true)
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true/*, prePostEnabled = true*/)
@Configuration
public class SecurityConfiguration {

    /*AuthenticationManager authenticationManager; // Interfejs/kontrakt dla procesu uwierzytelnienia użytkownika
        ProviderManager providerManager; // Podstawowa implementacja AuthenticationManager, deleguje proces uwierzytelnienia do jednego z obiektów AuthenticationProvider
            AuthenticationProvider authenticationProvider; // Interfejs/kontrakt dla obiektów realizujących uwierzytelnianie z wykorzystaniem konkretnego mechanizmu/implementacji
                DaoAuthenticationProvider daoAuthenticationProvider; // Jedna z implementacji AuthenticationProvider, ładuje dane o użytkowniku wykorzystując UserDetailsService i porównuje je z tymi podanymi w czasie logowani
                    UserDetailsService userDetailsService; // Interfejs/kontrakt usługi ładującej dane dotyczące użytkownika

    UsersDetailsManager usersDetailsManager; Interfejs/kontrakt pochodny UserDetailsService, pozwalający na zarządzanie użytkownikami
        InMemoryUserDetailsManager inMemoryUserDetailsManager; // Jedna z implementacji UsersDetailsManager, przechowuje informacje w pamięci

    PasswordEncoder passwordEncoder; //Interfejs/kontrakt pozwalający na hashowanie i porównywanie haseł
        BCryptPasswordEncoder bCryptPasswordEncoder; //Jedna z implementacji PasswordEncoder

    SecurityContextHolder securityContextHolder; // Przechowuje/udostępnia SecurityContext
        SecurityContext securityContext; // Kontener przechowujący Authentication
            Authentication authentication; // Reprezentuje dane uwierzytelniające jak i uwierzytelnionego użytkownika/system
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken; // Jedna z implementacji Authentication, zawiera login i hasło jako credentials
                    UserDetails userDetails; // Interfejs/kontrakt opisujący użytkownika
                    GrantedAuthority grantedAuthority; // Interfejs/kontrakt opisujący role/uprawnienia
                        SimpleGrantedAuthority simpleGrantedAuthority; // Jedna z implementacji SimpleGrantedAuthority

    AuthorizationManager authorizationManager; // Interfejs/kontrakt dla procesu autoryzacji
        AuthoritiesAuthorizationManager authoritiesAuthorizationManager; // Jedna z implementacji AuthorizationManager (role)*/

    @Bean
    public PasswordEncoder passwordEncoder() throws NoSuchAlgorithmException {
        var planText = NoOpPasswordEncoder.getInstance(); //deprecated
        var bcrypt = new BCryptPasswordEncoder(10, SecureRandom.getInstanceStrong());
        var scrypt = new SCryptPasswordEncoder(16384, 8, 1, 32, 64);

        Map<String, PasswordEncoder> encoders = Map.of(
                "noop", planText,
                "bcrypt", bcrypt,
                "scrypt", scrypt
        );
        return new DelegatingPasswordEncoder("bcrypt", encoders);
    }

    /*@Bean
    public UserDetailsManager userDetailsManager() {
        var user = User
                .withUsername("admin")
                .password("admin")
                .roles("ADMIN")
                //.authorities("create", "read", "delete")
                .build();
        return new InMemoryUserDetailsManager(user);
    }*/

   /* @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        var manager = new JdbcUserDetailsManager(dataSource);
        // manager.setUsersByUsernameQuery("select username, password, enabled from users where username = ?");
        // manager.setAuthoritiesByUsernameQuery("select username, authority from authorities where username = ?");
        return manager;
    }*/

    @Bean
    public InitializingBean initializingBean() {
    /*
        MODE_THREADLOCAL — Allows each thread to store its own details in the security context.
        In a thread-per-request web application, this is a common approach as each request has an individual thread.
        MODE_INHERITABLETHREADLOCAL — Similar to MODE_THREADLOCAL but also instructs Spring Security to copy the
        security context to the next thread in case of an asynchronous/@Async method
        MODE_GLOBAL — Makes all the threads of the application see the same security context instance
     */
        return () -> SecurityContextHolder.setStrategyName(MODE_INHERITABLETHREADLOCAL);
    }

    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, JpaUserDetailService jpaUserDetailService,
                                                   CustomCsrfTokenRepository csrfTokenRepository) throws Exception {
        return httpSecurity
                //.addFilterBefore(new DepartmentValidatorFilter(), UsernamePasswordAuthenticationFilter.class)
                //.addFilterAfter(customAuthenticationFilter, AnonymousAuthenticationFilter.class)
                //.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
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
                .cors(config -> {
                    CorsConfigurationSource source = request -> {
                        var corsConfig = new CorsConfiguration();
                        corsConfig.setAllowedOrigins(List.of("example.com", "example.org"));
                        corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                        corsConfig.setAllowedHeaders(List.of("*"));
                        return corsConfig;
                    };
                    config.configurationSource(source);
                })
                //.anonymous(AbstractHttpConfigurer::disable)
                .userDetailsService(jpaUserDetailService)
                .httpBasic(withDefaults())
                /*.httpBasic(config -> config
                        .realmName("training")
                        .authenticationEntryPoint(new CustomEntryPoint())
                )*/
                //.formLogin(withDefaults())
                .formLogin(config -> config
                                .loginPage("/login.html") // login is default
                                .defaultSuccessUrl("/index.html")
                        //.usernameParameter("username")
                        //.passwordParameter("password")
                        //.successHandler(implementacja AuthenticationSuccessHandler)
                        //.failureHandler(implementacja CustomAuthenticationFailureHandler)
                )
                .logout(config -> config
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout.html")) // logout is default
                        .logoutSuccessUrl("/login.html")
                        .invalidateHttpSession(true)
                )
                .authorizeHttpRequests(config -> config
                        .requestMatchers("/login.html").permitAll()
                        .requestMatchers("/api/tokens").permitAll()
                        //.requestMatchers("/api/payments/{id:^\\w{8}-\\w{4}-\\w{4}-\\w{4}-\\w{12}$}")
                        //.hasAnyRole("ADMIN", "MANAGER")
                        //.hasAuthority("read")
                        //.hasRole("ADMIN")
                        //.requestMatchers("/**").authenticated()
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
