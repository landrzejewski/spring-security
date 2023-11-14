### Linki
https://www.blitter.se/utils/basic-authentication-header-generator
https://github.com/datablist/sample-csv-files
https://cloudentity.com/developers/basics/oauth-extensions/authorization-code-with-pkce/
https://stackoverflow.com/questions/60766213/whats-the-alternative-to-password-grant-now-that-it-is-deprecated-oauth-2-0

### Generowanie certyfikatu SSL
openssl req -newkey rsa:2048 -x509 -keyout key.pem -out cert.pem -days 365
openssl pkcs12 -export -in cert.pem -inkey key.pem -out certificate.p12 -name "certificate"

### Definiowanie First login flow dla logowania przez GitHub
Authentication -> Create flow (detect existing user flow, Basic flow) -> Add step (Detect existing broker user, Automatically set existing user)
Identity providers -> github -> First login flow -> detect existing user flow

### Zadania
- Dodaj filtr logujący informację zawarte w SecurityContext. W przypadku
  kiedy użytkownik nie jest zalogowany, filtr powinien o tym poinformować

- Rozszerz komponenty Spring Security tak, aby możliwe było uwierzytelnianie i autoryzacja
  użytkowników na podstawie tokenów jwt. Użyj biblioteki https://github.com/auth0/java-jwt
  Wykorzystaj poniższy algorytm do podpisania tokenu.
```
public static final Algorithm ALGORITHM = Algorithm.HMAC256("secret");
```

- Zaimplementuj niestandardowy AuthorizationManager, tak aby było można autoryzować
  dostęp do zasobów webowych na podstawie konfiguracji ładowanej z bazy (rola/url)

- Napisz aspekt, ograniczający dostęp do wybranych metod beanów - pozytywna autoryzacja w określonych godzinach
  wymaga jednej ze wskazanych ról

- Zaszyfruj przykładowe dane np. w formacie csv. Zaimplementuj usługę REST, która będzie ładować zaszyfrowane
  wcześniej dane, deszyfrować je oraz filtrować ze względu na posiadaną rolę

- Bazując na przykładach konfiguracji Spring/OAuth2/Keycloak, spróbuj skonfigurować bezpieczeństwo aplikacji
  reaktywnej z wykorzystaniem protokołu OAuth2

