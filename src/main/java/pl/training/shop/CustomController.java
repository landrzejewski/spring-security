package pl.training.shop;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RequestMapping("api/users")
@RestController
public class CustomController {

    // @PreAuthorize("false")
    @GetMapping("me")
    public Mono<Authentication> getInfo(Mono<Authentication> authenticationMono) {
        return authenticationMono;
    }

}
