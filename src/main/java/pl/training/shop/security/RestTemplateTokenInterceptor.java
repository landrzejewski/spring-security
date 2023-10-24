package pl.training.shop.security;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class RestTemplateTokenInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        Token.getAuthorizationHeaderValue()
                .ifPresent(headerValue -> request.getHeaders().set(AUTHORIZATION, headerValue));
        return execution.execute(request, body);
    }

}
