package pl.training.shop.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import pl.training.shop.security.users.JpaUserRepository;
import pl.training.shop.security.users.UserEntity;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SecurityInitializer implements ApplicationRunner {

    private static final String USER_EMAIL = "admin@training.pl";
    private static final String ADMIN_ROLE = "ROLE_ADMIN";

    private final JpaUserRepository userRepository;

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.findByEmail(USER_EMAIL).isEmpty()) {
            var user = new UserEntity();
            user.setId(nextId());
            user.setEmail(USER_EMAIL);
            user.setPassword("admin");
            user.setRole(ADMIN_ROLE);
            user.setActive(true);
            userRepository.save(user);
        }
    }
    private String nextId() {
        return UUID.randomUUID().toString();
    }

}
