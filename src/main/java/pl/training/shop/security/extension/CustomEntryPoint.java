package pl.training.shop.security.extension;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import java.io.IOException;

import static jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

@Data
public class CustomEntryPoint implements AuthenticationEntryPoint {

    private String realmName = "default";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.addHeader("SECURITY_STATUS", "UNAUTHORIZED");
        response.setHeader("WWW-Authenticate", "Basic realm=\"" + this.realmName + "\"");
        response.setStatus(SC_UNAUTHORIZED);
    }

}
