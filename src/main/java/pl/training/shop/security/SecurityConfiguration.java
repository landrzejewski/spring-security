package pl.training.shop.security;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.core.context.SecurityContextHolder.MODE_INHERITABLETHREADLOCAL;

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
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(config -> config.ignoringRequestMatchers("/api/**"))
                //.httpBasic(withDefaults())
                /*.httpBasic(config -> config
                        .realmName("training")
                        .authenticationEntryPoint(new CustomEntryPoint())
                )*/
                //.formLogin(withDefaults())
                .formLogin(config -> config
                        .loginPage("/login.html")
                        .defaultSuccessUrl("/index.html")
                        //.usernameParameter("username")
                        //.passwordParameter("password")
                )
                .authorizeHttpRequests(config -> config
                        .requestMatchers("/login.html").permitAll()
                        .anyRequest().authenticated()
                )
                .build();
    }

}
