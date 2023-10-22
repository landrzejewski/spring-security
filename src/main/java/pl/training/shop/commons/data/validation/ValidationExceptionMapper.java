package pl.training.shop.commons.data.validation;

import org.mapstruct.Mapper;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static java.util.stream.Collectors.joining;

@Mapper(componentModel = "spring")
public interface ValidationExceptionMapper {

    String KEY_VALUE_SEPARATOR = " ";
    String DELIMITER = ", ";

    default String getValidationErrors(MethodArgumentNotValidException methodArgumentNotValidException) {
        return methodArgumentNotValidException.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fieldError -> fieldError.getField() + KEY_VALUE_SEPARATOR + fieldError.getDefaultMessage())
                .collect(joining(DELIMITER));
    }

}
