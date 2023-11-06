package pl.training.shop.security.extensions.jwt;

import com.auth0.jwt.JWT;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.training.shop.security.users.JpaUsersDetailsServiceAdapter;

import java.time.Instant;

import static java.time.temporal.ChronoUnit.SECONDS;
import static pl.training.shop.security.extensions.jwt.JwtConfig.*;

@RequestMapping("api/tokens")
@RestController
@RequiredArgsConstructor
public class JwtLoginRestController {

    private final JpaUsersDetailsServiceAdapter userDetailsService;

    @PostMapping
    public JwtDto login(@RequestBody CredentialsDto credentialsDto) {
        var user = userDetailsService.verify(credentialsDto.getLogin(), credentialsDto.getPassword());
        var token = JWT.create()
                .withIssuer(ISSUER)
                .withClaim(USER_CLAIM, user.getEmail())
                .withClaim(ROLES_CLAIM, user.getRoles())
                .withExpiresAt(Instant.now().plus(3600, SECONDS))
                .sign(ALGORITHM);
        return new JwtDto(token);
    }

}
