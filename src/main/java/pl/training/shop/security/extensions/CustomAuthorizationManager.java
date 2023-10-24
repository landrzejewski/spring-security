package pl.training.shop.security.extensions;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

@Component
public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final Map<String, Set<String>> mappings = Map.of(
            "ROLE_ADMIN", Set.of("/api/users/me")
    );

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext requestContext) {
        var url = requestContext.getRequest().getRequestURI();
        var role = authentication.get()
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst();
        return role.map(s -> new AuthorizationDecision(mappings.get(s).contains(url)))
                .orElseGet(() -> new AuthorizationDecision(false));
    }

}
