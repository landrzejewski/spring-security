package pl.training.shop.security.users;

import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface JpaUsersMapper {

    User toDomain(UserEntity userEntity);

}
