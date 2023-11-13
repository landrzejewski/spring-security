package pl.training.shop.security.users;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JpaUserDetailsServiceAdapter implements UserDetailsService {

    private final JpaUsersRepository usersRepository;
    private final JpaUsersMapper usersMapper;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return usersRepository.findByEmail(email)
                .map(usersMapper::toDomain)
                .orElseThrow(() -> new UsernameNotFoundException("User %s not found".formatted(email)));
    }

}
