package pl.training.shop.commons.data.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Constraint(validatedBy = MoneyValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Money {

    String message() default "incorrect currency";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    double minValue() default 100.0;

}
