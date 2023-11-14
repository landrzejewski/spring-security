package pl.training.shop.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class SecretsPostProcessor implements EnvironmentPostProcessor {

    private static final String PROPERTY_SOURCE_NAME = "secrets";
    private static final String SECRETS_FILE = "secrets.properties";

    private final TextEncryptor textEncryptor = Encryptors.text("secret", "a260387e5b4eb060");

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        var rootPath = getClass().getClassLoader().getResource("").getPath();
        var decryptedProperties = new Properties();
        var properties = new Properties();
        try (var fis = new FileInputStream(rootPath + SECRETS_FILE)) {
            properties.load(fis);
            properties.forEach((key, value) -> decryptedProperties.put(key, textEncryptor.decrypt(value.toString())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        var propertySource = new PropertiesPropertySource(PROPERTY_SOURCE_NAME, decryptedProperties);
        environment.getPropertySources().addFirst(propertySource);
    }

}
