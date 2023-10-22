package pl.training.shop.commons.aspect;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import java.util.concurrent.locks.ReentrantReadWriteLock;

import static pl.training.shop.commons.aspect.Lock.LockType.WRITE;

@Aspect
@Component
public class LockAspect {

    @Around("@annotation(lock)")
    public Object lock(ProceedingJoinPoint joinPoint, Lock lock) throws Throwable {
        var newLock = new ReentrantReadWriteLock();
        var targetLock = lock.type() == WRITE ? newLock.writeLock() : newLock.readLock();
        targetLock.lock();
        try {
            return joinPoint.proceed();
        } finally {
            targetLock.unlock();
        }
    }

}
