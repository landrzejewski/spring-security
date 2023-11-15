### Linki
https://www.blitter.se/utils/basic-authentication-header-generator
https://github.com/datablist/sample-csv-files
https://www.baeldung.com/apache-commons-csv
https://cloudentity.com/developers/basics/oauth-extensions/authorization-code-with-pkce/
https://stackoverflow.com/questions/60766213/whats-the-alternative-to-password-grant-now-that-it-is-deprecated-oauth-2-0

### Generowanie certyfikatu SSL
openssl req -newkey rsa:2048 -x509 -keyout key.pem -out cert.pem -days 365
openssl pkcs12 -export -in cert.pem -inkey key.pem -out certificate.p12 -name "certificate"

### Zadania
- Zaimplementuj niestandardowy AuthorizationManager, tak aby było można autoryzować
  dostęp do zasobów webowych na podstawie konfiguracji ładowanej z bazy (rola/url)

- Dodaj filtr logujący informację zawarte w SecurityContext. W przypadku
kiedy użytkownik nie jest zalogowany, filtr powinien o tym poinformować

- Rozszerz komponenty Spring Security tak, aby możliwe było uwierzytelnianie i autoryzacja
użytkowników na podstawie tokenów jwt. Użyj biblioteki https://github.com/auth0/java-jwt 
Wykorzystaj poniższy algorytm do podpisania tokenu.
```
public static final Algorithm ALGORITHM = Algorithm.HMAC256("secret");
```

- Zaimplementuj usługę rest, zwracającą dane z zaszyfrowanych plików csv. Przed zwróceniem 
dane powinny być przefiltrowane ze względu na treść oraz rolę użytkownika (JPA QL expressions, adnotacje).
Dostęp do endpointów rest zabezpiecz z wykorzystaniem protokołu OpenID (Spring, Keycloak). 

https://github.com/landrzejewski/clean-architecture


https://tinyurl.com/yzc2w8jy
