package pl.training.shop.commons.aspect;

import lombok.extern.java.Log;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import pl.training.shop.commons.aspect.Timer.TimeUnit;

import static pl.training.shop.commons.aspect.Timer.TimeUnit.NS;

// @Order(100)
@Aspect
@Component
@Log
public class TimerAspect implements Ordered {

    @Around("@annotation(timer)")
    public Object log(ProceedingJoinPoint joinPoint, Timer timer) throws Throwable {
        var timeUnit = timer.timeUnit();
        var startTime = getTime(timeUnit);
        var result = joinPoint.proceed();
        var endTime = getTime(timeUnit);
        var totalTime = endTime - startTime;
        log.info("Method %s executed in %d %s".formatted(joinPoint.getSignature(), totalTime,
                timeUnit.name().toLowerCase()));
        return result;
    }

    private long getTime(TimeUnit timeUnit) {
        return timeUnit == NS ? System.nanoTime() : System.currentTimeMillis();
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE;
    }

}
