package pl.training.shop.security.users;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Table(name = "users")
@Entity(name = "User")
@Getter
@Setter
@EqualsAndHashCode(of = "id")
public class UserEntity {

    @Id
    private String id;
    @Column(unique = true)
    private String email;
    private String name;
    private String password;
    private boolean active;
    private String role;

}
