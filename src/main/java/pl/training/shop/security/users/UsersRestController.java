package pl.training.shop.security.users;

import org.springframework.scheduling.annotation.Async;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutorService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

@RequestMapping("api/users")
@RestController
public class UsersRestController {

    @GetMapping("me")
    public Authentication getUserInfo(Authentication authentication, Principal principal) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth;
    }

    @Async
    @GetMapping("/async-task")
    public String calculations() throws Exception {
        Callable<String> task = () -> SecurityContextHolder.getContext().getAuthentication().getName();
        var executor = Executors.newFixedThreadPool(10);

        /*try {
            var taskWithSecurityContext = new DelegatingSecurityContextCallable<>(task);
            return executor.submit(taskWithSecurityContext).get();
        } finally {
            executor.shutdown();
        }*/

        var executorServiceWithSecurityContext = new DelegatingSecurityContextExecutorService(executor);
        try {
            return executor.submit(task).get();
        } finally {
            executorServiceWithSecurityContext.shutdown();
        }
    }

       /*
        DelegatingSecurityContextExecutor - Implements the Executor interface and is designed to
        decorate an Executor object with the capability of forwarding the security context to the threads
        created by its pool

        DelegatingSecurityContextExecutorService - Implements the ExecutorService interface and
        is designed to decorate an ExecutorService object with the capability of forwarding the security context to the threads
        created by its pool.

        DelegatingSecurityContextScheduledExecutorService - Implements the ScheduledExecutorService interface and is designed to
        decorate a ScheduledExecutorService object with the capability of forwarding the security context to
        the threads created by its pool.

        DelegatingSecurityContextRunnable - Implements the Runnable interface and represents a task
        that is executed on a different thread without returning a response. Above a normal
        Runnable, it is also able to propagate a security context to use on the new thread.

        DelegatingSecurityContextCallable - Implements the Callable interface and represents a task
        that is executed on a different thread and that will eventually return a response. Above a normal
        Callable, it is also able to propagate a security context to use on the new thread.
         */

}
