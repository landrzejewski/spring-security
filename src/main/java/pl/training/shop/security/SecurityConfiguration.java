package pl.training.shop.security;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import pl.training.shop.security.extensions.CustomEntryPoint;
import pl.training.shop.security.extensions.SecurityLoggingFilter;
import pl.training.shop.security.extensions.jwt.JwtAuthenticationFilter;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

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

    UserDetailsManager usersDetailsManager; //Interfejs/kontrakt pochodny UserDetailsService, pozwalający na zarządzanie użytkownikami
        InMemoryUserDetailsManager inMemoryUserDetailsManager; // Jedna z implementacji UsersDetailsManager, przechowuje informacje w pamięci

    PasswordEncoder passwordEncoder; //Interfejs/kontrakt pozwalający na hashowanie i porównywanie haseł
        BCryptPasswordEncoder bCryptPasswordEncoder; //Jedna z implementacji PasswordEncoder

    SecurityContextHolder securityContextHolder; // Przechowuje/udostępnia SecurityContext
        SecurityContext securityContext; // Kontener przechowujący Authentication
            Authentication authentication; // Reprezentuje dane uwierzytelniające, jak i uwierzytelnionego użytkownika/system
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
                .password("123")
                .roles("ADMIN")
                .authorities("create", "read", "write")
                .build();
        return new InMemoryUserDetailsManager(user);
    }*/

    /*@Bean
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
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, SecurityLoggingFilter securityLoggingFilter,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        return httpSecurity
                //.addFilterBefore(secretAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(securityLoggingFilter, ExceptionTranslationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
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

    @Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }

    public static void main(String args[]) {
        String salt = KeyGenerators.string().generateKey();
        String password = "secret";
        String valueToEncrypt = "admin";

        var bytesEncryptor = Encryptors.standard(password, salt);
        byte [] encryptedBytes = bytesEncryptor.encrypt(valueToEncrypt.getBytes());
        byte [] decryptedBytes = bytesEncryptor.decrypt(encryptedBytes);

        var textEncryptor = Encryptors.text(password, salt);
        var encryptedText = textEncryptor.encrypt(valueToEncrypt);
        var decryptedText = textEncryptor.decrypt(encryptedText);
    }

}
