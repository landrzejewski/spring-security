package pl.training.shop.commons.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

import static pl.training.shop.commons.aspect.Annotations.applyArgumentOperator;

@Aspect
@Component
public class MinLengthAspect {

    @Before("execution(* *(@pl.training.shop.commons.aspect.MinLength (*)))")
    public void validate(JoinPoint joinPoint) throws NoSuchMethodException {
        applyArgumentOperator(joinPoint, MinLength.class, (String argument, MinLength minLength) -> {
            if (argument.length() < minLength.value()) {
                throw new IllegalArgumentException("Value is too short, minimum length is: " + minLength.value());
            }
        });
    }

}
