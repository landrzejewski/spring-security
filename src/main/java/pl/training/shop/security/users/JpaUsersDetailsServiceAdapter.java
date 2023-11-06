package pl.training.shop.security.users;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaUsersDetailsServiceAdapter implements UserDetailsService {

    private final JpaUsersRepository repository;
    private final JpaUsersMapper mapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return repository.findByEmail(email)
                .map(mapper::toDomain)
                .orElseThrow(() -> new UsernameNotFoundException("User %s not found".formatted(email)));
    }

    public User verify(String email, String password) {
        var user = loadUserByUsername(email);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }
        return (User) user;
    }

}
