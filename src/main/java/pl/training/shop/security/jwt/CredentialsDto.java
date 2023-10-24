package pl.training.shop.security.jwt;

import lombok.Data;

@Data
public class CredentialsDto {

    private String login;
    private String password;

}
