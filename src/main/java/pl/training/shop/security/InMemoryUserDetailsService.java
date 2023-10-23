package pl.training.shop.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

//@Component
public class InMemoryUserDetailsService implements UserDetailsService {

    private static final String ADMIN_USER_NAME = "admin";

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!username.equalsIgnoreCase(ADMIN_USER_NAME)) {
            throw new UsernameNotFoundException("User %s not found".formatted(username));
        }
        return User.withUsername(ADMIN_USER_NAME)
                .password("admin")
                .roles("ADMIN")
                .build();
    }

}
