package pl.training.shop.security.jwt;

import com.auth0.jwt.algorithms.Algorithm;

public class JwtConfig {

    public static final String ISSUER = "https://localhost:8080";
    public static final String USER_CLAIM = "user";
    public static final String ROLE_CLAIM = "role";
    public static final Algorithm ALGORITHM = Algorithm.HMAC256("secret");

}
