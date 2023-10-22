package pl.training.shop.commons.aspect;

import lombok.RequiredArgsConstructor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.DefaultTransactionDefinition;

@Aspect
@Component
@RequiredArgsConstructor
public class TransactionAspect {

    private final PlatformTransactionManager platformTransactionManager;

    @Around("@annotation(pl.training.shop.commons.aspect.Atomic) || within(@pl.training.shop.commons.aspect.Atomic *)")
    public Object runWithTransaction(ProceedingJoinPoint joinPoint) throws Throwable {
        var annotation = Annotations.findAnnotation(joinPoint, Atomic.class);
        var transactionDefinition = transactionDefinition(annotation);
        var transactionStatus = platformTransactionManager.getTransaction(transactionDefinition);
        try {
            var result = joinPoint.proceed();
            platformTransactionManager.commit(transactionStatus);
            return result;
        } catch (Throwable throwable) {
            transactionStatus.setRollbackOnly();
            throw throwable;
        }
    }

    private TransactionDefinition transactionDefinition(Atomic atomic) {
        var transactionDefinition = new DefaultTransactionDefinition();
        transactionDefinition.setTimeout(atomic.timeoutInMilliseconds());
        return transactionDefinition;
    }

}
