### Linki
https://www.blitter.se/utils/basic-authentication-header-generator
https://github.com/datablist/sample-csv-files
https://www.baeldung.com/apache-commons-csv
https://cloudentity.com/developers/basics/oauth-extensions/authorization-code-with-pkce/
https://stackoverflow.com/questions/60766213/whats-the-alternative-to-password-grant-now-that-it-is-deprecated-oauth-2-0

### Zadania
- Zaimplementuj niestandardowy AuthorizationManager, tak aby było można autoryzować
  dostęp do zasobów webowych na podstawie konfiguracji ładowanej z bazy (rola/url)

- Dodaj filtr logujący informację zawarte w SecurityContext. W przypadku
kiedy użytkownik nie jest zalogowany, filtr powinien o tym poinformować

- Rozszerz komponenty Spring Security tak, aby możliwe było uwierzytelnianie i autoryzacja
użytkowników na podstawie tokenów jwt. Użyj biblioteki com.auth0:java-jwt:4.3.0

- Zaimplementuj usługę rest, zwracającą dane z zaszyfrowanych plików csv. Przed zwróceniem 
dane powinny być przefiltrowane ze względu na treść oraz rolę użytkownika (JPA QL expressions, adnotacje).
Dostęp do endpointów rest zabezpiecz z wykorzystaniem protokołu OpenID (Spring, Keycloak). 
