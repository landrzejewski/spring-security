package pl.training.shop.security.extensions.jwt;

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

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String TOKEN_PREFIX = "bearer ";
    private static final String TOKENS_ENDPOINT = "api/tokens";
    private static final String EMPTY = "";

    private final AuthenticationConfiguration authenticationConfiguration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().contains(TOKENS_ENDPOINT)) {
            filterChain.doFilter(request, response);
        } else {
            var authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader == null) {
                response.setStatus(SC_UNAUTHORIZED);
            } else if (authorizationHeader.startsWith(TOKEN_PREFIX)) {
                var token = authorizationHeader.replace(TOKEN_PREFIX, EMPTY);
                var jwtAuthentication = new JwtAuthentication(token);
                try {
                    var authentication = authenticationConfiguration.getAuthenticationManager()
                            .authenticate(jwtAuthentication);
                    var securityContext = SecurityContextHolder.createEmptyContext();
                    securityContext.setAuthentication(authentication);
                    SecurityContextHolder.setContext(securityContext);
                    filterChain.doFilter(request, response);
                } catch (Exception exception) {
                    SecurityContextHolder.createEmptyContext();
                    response.setStatus(SC_UNAUTHORIZED);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }

}
