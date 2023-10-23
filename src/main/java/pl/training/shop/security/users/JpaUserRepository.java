package pl.training.shop.security.users;

import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface JpaUserRepository extends CrudRepository<UserEntity, String> {

    Optional<UserEntity> findByEmail(String email);

}
