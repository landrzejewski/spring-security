package pl.training.shop.security.extensions;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

//@Component
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private static final String PLAIN_AUTHORIZATION_PREFIX = "Plain ";
    private static final String EMPTY = "";

    private final AuthenticationConfiguration authenticationConfiguration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith(PLAIN_AUTHORIZATION_PREFIX)) {
            filterChain.doFilter(request, response);
        } else {
            var data = authorizationHeader.replace(PLAIN_AUTHORIZATION_PREFIX, EMPTY)
                    .split("\\s");
            var plainAuthentication = new PlainAuthentication(data[0], data[1]);
            try {
                var authentication = authenticationConfiguration.getAuthenticationManager()
                        .authenticate(plainAuthentication);
                var securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(securityContext);
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                response.setStatus(SC_UNAUTHORIZED);
            }
        }
    }

    /*@Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return true;
    }*/

}
