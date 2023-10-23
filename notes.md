Basic Authorization header generator
https://www.blitter.se/utils/basic-authentication-header-generator


Zadania
- Dodaj filtr logujący informację zawarte w SecurityContext. W przypadku
kiedy użytkownik nie jest zalogowany, filtr powinien o tym poinformować

- Zaimplementuj niestandardowy AuthorizationManager, tak aby było można autoryzować 
dostęp do zasobów webowych na podstawie konfiguracji ładowanej z bazy (rola/url)

- Rozszerz komponenty Spring Security tak, aby możliwe było uwierzytelnianie i autoryzacja
użytkowników na podstawie tokenów jwt. Użyj biblioteki com.auth0:java-jwt:4.3.0
