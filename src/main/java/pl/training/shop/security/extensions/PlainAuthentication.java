package pl.training.shop.security.extensions;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import static java.util.Collections.emptyList;

@Getter
public class PlainAuthentication extends AbstractAuthenticationToken {

    private final String login;
    private final String password;

    public PlainAuthentication(String login, String password) {
        super(emptyList());
        this.login = login;
        this.password = password;
    }

    @Override
    public Object getCredentials() {
        return password;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

}
