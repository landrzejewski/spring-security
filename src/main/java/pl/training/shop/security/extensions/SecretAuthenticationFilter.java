package pl.training.shop.security.extensions;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

//@Component
@RequiredArgsConstructor
public class SecretAuthenticationFilter extends OncePerRequestFilter {

    private static final String SECRET_AUTHORIZATION_PREFIX = "SECRET ";

    private final AuthenticationConfiguration authenticationConfiguration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(SECRET_AUTHORIZATION_PREFIX)) {
            filterChain.doFilter(request, response);
        } else {
            var secret = authHeader.replace(SECRET_AUTHORIZATION_PREFIX, "");
            var secretAuthentication =  new SecretAuthentication(secret.toCharArray());
            try {
                var authenticationResult = authenticationConfiguration.getAuthenticationManager()
                        .authenticate(secretAuthentication);
                var securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authenticationResult);
                SecurityContextHolder.setContext(securityContext);
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                response.setStatus(SC_UNAUTHORIZED);
            }
        }
    }

}
