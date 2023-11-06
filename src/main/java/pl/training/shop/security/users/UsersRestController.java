package pl.training.shop.security.users;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RequestMapping("api/users")
@RestController
public class UsersRestController {

    @GetMapping("me")
    public Authentication getUserInfo(Authentication authentication, Principal principal) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth;
    }

}
