package pl.training.shop.security.extensions;

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
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER_PREFIX = "API_KEY ";
    private static final String EMPTY = "";

    private final AuthenticationConfiguration authenticationConfiguration;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(AUTH_HEADER_PREFIX)) {
            filterChain.doFilter(request, response);
        } else {
            var apiKey = authHeader.replace(AUTH_HEADER_PREFIX, EMPTY);
            var authentication = new ApiKeyAuthentication(apiKey);
            try {
                var resultAuthentication = authenticationConfiguration.getAuthenticationManager()
                        .authenticate(authentication);
                var securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(resultAuthentication);
                SecurityContextHolder.setContext(securityContext);
                filterChain.doFilter(request, response);
            } catch (AuthenticationException authenticationException) {
                response.setStatus(SC_UNAUTHORIZED);
            } catch (Exception exception) {
                throw new ServletException(exception);
            }
        }
    }

}
