package pl.training.shop.security.csrf;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaTokenRepository extends JpaRepository<TokenEntity, Integer> {

    Optional<TokenEntity> findTokenByIdentifier(String identifier);
}
