package pl.training.shop.security.extensions.jwt;

import com.auth0.jwt.JWT;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.training.shop.security.users.JpaUserDetailsServiceAdapter;
import pl.training.shop.security.users.User;

import java.time.Instant;

import static java.time.temporal.ChronoUnit.SECONDS;
import static pl.training.shop.security.extensions.jwt.JwtConfig.*;

@RequestMapping("api/tokens")
@RestController
@RequiredArgsConstructor
public class JwtLoginRestController {

    private final JpaUserDetailsServiceAdapter userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping
    public JwtDto login(@RequestBody CredentialsDto credentialsDto) {
        var user = verify(credentialsDto.getLogin(), credentialsDto.getPassword());
        var token = JWT.create()
                .withIssuer(ISSUER)
                .withClaim(USER_CLAIM, user.getEmail())
                .withClaim(ROLES_CLAIM, user.getRoles())
                .withExpiresAt(Instant.now().plus(3600, SECONDS))
                .sign(ALGORITHM);
        return new JwtDto(token);
    }

    private User verify(String email, String password) {
        var user = userDetailsService.loadUserByUsername(email);
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }
        return (User) user;
    }

}
