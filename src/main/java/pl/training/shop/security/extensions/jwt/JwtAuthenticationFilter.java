package pl.training.shop.security.extensions.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String TOKEN_PREFIX = "bearer ";
    private static final String EMPTY = "";

    private final AuthenticationConfiguration authenticationConfiguration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            var token = authorizationHeader.replace(TOKEN_PREFIX, EMPTY);
            var jwtAuthentication = new JwtAuthentication(token);
            try {
                var resultAuthentication = authenticationConfiguration.getAuthenticationManager()
                        .authenticate(jwtAuthentication);
                var securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(resultAuthentication);
                SecurityContextHolder.setContext(securityContext);
                filterChain.doFilter(request, response);
            } catch (AuthenticationException exception) {
                response.setStatus(SC_UNAUTHORIZED);
            } catch (Exception exception) {
                throw new ServletException(exception.getCause());
            }
        }
        filterChain.doFilter(request, response);
    }

}
