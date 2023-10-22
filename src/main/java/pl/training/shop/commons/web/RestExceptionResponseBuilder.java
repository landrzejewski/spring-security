package pl.training.shop.commons.web;

import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
@RequiredArgsConstructor
public class RestExceptionResponseBuilder {

    private static final String EMPTY_DESCRIPTION = "";

    private final MessageSource messageSource;

    public ResponseEntity<ExceptionDto> build(Exception exception, HttpStatus status, Locale locale) {
        return build(getLocalizedMessage(exception, locale), status);
    }

    public ResponseEntity<ExceptionDto> build(String description, HttpStatus status) {
        return ResponseEntity.status(status)
                .body(new ExceptionDto(description));
    }

    public String getLocalizedMessage(Exception exception, Locale locale, String...parameters) {
        var key = exception.getClass().getSimpleName();
        return messageSource.getMessage(key, parameters, EMPTY_DESCRIPTION, locale);
    }

}
