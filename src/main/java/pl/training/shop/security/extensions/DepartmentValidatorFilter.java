package pl.training.shop.security.extensions;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;

public class DepartmentValidatorFilter implements Filter {

    private static final String DEPARTMENT_HEADER = "Department";

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        var httpRequest = (HttpServletRequest) servletRequest;
        var httpResponse = (HttpServletResponse) servletResponse;
        var departmentHeader = httpRequest.getHeader(DEPARTMENT_HEADER);
        if (departmentHeader == null || departmentHeader.isBlank()) {
            httpResponse.setStatus(SC_BAD_REQUEST);
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

}
