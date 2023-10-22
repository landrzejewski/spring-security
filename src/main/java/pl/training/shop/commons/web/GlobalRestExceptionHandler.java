package pl.training.shop.commons.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import pl.training.shop.commons.data.validation.ValidationExceptionMapper;

import java.util.Locale;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Log
@ControllerAdvice(annotations = RestController.class)
@RequiredArgsConstructor
public class GlobalRestExceptionHandler {

    private final RestExceptionResponseBuilder responseBuilder;
    private final ValidationExceptionMapper mapper;

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ExceptionDto> onException(Exception exception, Locale locale) {
        log.warning("Exception: " + exception.getClass().getName());
        exception.printStackTrace();
        return responseBuilder.build(exception, INTERNAL_SERVER_ERROR, locale);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ExceptionDto> onMethodArgumentNotValidException(MethodArgumentNotValidException methodArgumentNotValidException, Locale locale) {
        var validationErrors = mapper.getValidationErrors(methodArgumentNotValidException);
        var description = responseBuilder.getLocalizedMessage(methodArgumentNotValidException, locale, validationErrors);
        return responseBuilder.build(description, BAD_REQUEST);
    }

}
