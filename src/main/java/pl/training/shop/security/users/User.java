package pl.training.shop.security.users;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User implements UserDetails, CredentialsContainer {

    public static final String ROLES_SEPARATOR = ",";

    private String id;
    private String email;
    private String name;
    private String password;
    private boolean active;
    private String roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        var a = Arrays.stream(roles.split(ROLES_SEPARATOR))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        return a;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return active;
    }

    @Override
    public boolean isAccountNonLocked() {
        return active;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return active;
    }

    @Override
    public boolean isEnabled() {
        return active;
    }

    @Override
    public void eraseCredentials() {
        password = "";
    }

}
