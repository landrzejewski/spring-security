package pl.training.shop.security.extensions.jwt;

import com.auth0.jwt.algorithms.Algorithm;

public class JwtConfig {

    public static final String ISSUER = "https://localhost";
    public static final String USER_CLAIM = "user";
    public static final String ROLES_CLAIM = "roles";
    public static final Algorithm ALGORITHM = Algorithm.HMAC256("secret");

}
