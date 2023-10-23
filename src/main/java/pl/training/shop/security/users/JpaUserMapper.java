package pl.training.shop.security.users;

import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface JpaUserMapper {

    User toDomain(UserEntity userEntity);

}
