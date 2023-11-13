package pl.training.shop.security.users;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaUsersRepository extends JpaRepository<UserEntity, String> {

    Optional<UserEntity> findByEmail(String email);

}
