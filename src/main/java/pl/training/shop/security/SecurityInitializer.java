package pl.training.shop.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import pl.training.shop.security.users.JpaUsersRepository;
import pl.training.shop.security.users.UserEntity;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class SecurityInitializer implements ApplicationRunner {

    public static final String USER_EMAIL = "admin@training.pl";
    public static final String USER_NAME = "admin";
    public static final String USER_ROLES = "ROLE_ADMIN,ROLE_MANAGER";

    private final JpaUsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (usersRepository.findByEmail(USER_EMAIL).isEmpty()) {
            var user = new UserEntity();
            user.setId(UUID.randomUUID().toString());
            user.setEmail(USER_EMAIL);
            user.setName(USER_NAME);
            user.setPassword("admin");
            user.setRoles(USER_ROLES);
            user.setActive(true);
            usersRepository.save(user);
        }
        // System.out.println(passwordEncoder.encode("admin"));
    }

}
