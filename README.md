# spring-security-demo

This is a Java code snippet for configuring security in a Spring WebFlux application using Spring Security.
The code demonstrates how to enable security for a springboot application and customize it.

To enable security for reactive springboot application, we need  @EnableWebFluxSecurity annotation. For this we can create a separate class SecurityConfig.java for Security configuration
and have this annotaiton on this class. Since this is our configuration class, we need to tell Spring about with help of annotation @Configuration.

Now, if we start our application with this basic setup, you see a default system generated password in the logs of the application.
```
Using generated security password: ee795ded-8dff-4753-957a-d
```
We will see below where is this password coming from and what is the username (it's user if you want to access the login page http://localhost:{port} )

Spring Security handles security by applying servlet filters to HTTP requests.

If we do not specify any security configuration for user,/password, url protection etc. default configuration is used.

Two main default configuration classes to look at are ServerHttpSecurityConfiguration and WebFluxSecurityConfiguration.

ServerHttpSecurityConfiguration - This configuration class initialized the default beans needed for implementing security. e.g.  ReactiveAuthenticationManager,  ReactiveUserDetailsService, PasswordEncoder. These are the building blocks of Spring security.  The default implementation of the interface
ReactiveUserDetailsService which is MapReactiveUserDetailsService will tell us that the default username /password comes from
SecurityProperties class which has a inner User class with fields name and password.

```
public static class User {

   /**
    * Default user name.
    */
   private String name = "user";

   /**
    * Password for the default user name.
    */
   private String password = UUID.randomUUID().toString();
```

WebFluxSecurityConfiguration helps us define default requests that needs to be protected, login form etc.

```
/**
 * The default {@link ServerHttpSecurity} configuration.
 * @param http
 * @return
 */
private SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
   http.authorizeExchange().anyExchange().authenticated();
   if (isOAuth2Present && OAuth2ClasspathGuard.shouldConfigure(this.context)) {
      OAuth2ClasspathGuard.configure(this.context, http);
   }
   else {
      http.httpBasic();
      http.formLogin();
   }
   SecurityWebFilterChain result = http.build();
   return result;
}
```

Few things to notice -
1. By default every request needs to be authenticated
2. Default formLogin is used along with http basic security .

In order for us to customize any of the security aspect, the respective bean from the above two default configurations classes needs to be overridden.

Example -
To add user with password,  we can create an instance of MapReactiveUserDetailsService in our SecurityConfig.java

```
@Bean
public MapReactiveUserDetailsService userDetailsService() {

    log.info("MapReactiveUserDetailsService initialized!");

    //User.withDefaultPasswordEncoder is not at all recommended for
    // Production environment. I am just using it for demo purpose.
    UserDetails user = User.withDefaultPasswordEncoder()
                           .username("barfi")
                           .password("woof")
                           .roles("read")
                           .build();
    return new MapReactiveUserDetailsService(user);
}
```

Now, if we start the application we won't see system generated password in the logs. And if we navigate to http://localhost:{port} we can login using barfi/woof credentails.

MapReactiveUserDetailsService have multiple constructors out of which one can take multiple UserDetails as well.

The above goal of user creation can also be achieved by creating bean of type ReactiveAuthenticationManager

```
@Bean
ReactiveAuthenticationManager customersAuthenticationManager() {

    log.info("ReactiveAuthenticationManager initialized!");

    return authentication -> user(authentication)
            .switchIfEmpty(
                    Mono.error(new UsernameNotFoundException(authentication.getName() + "Not found")))
            .map(b -> new UsernamePasswordAuthenticationToken(b.getName()
                    , String.valueOf(b.getCredentials()),
                                                              Arrays.asList()));
}

private Mono<Authentication> user(Authentication authentication) {

    String user = authentication.getName();
    String password = String.valueOf(authentication.getCredentials());

    if (user.equals("barfi") && password.equals("woof")){
        return Mono.just(authentication);
    }

    return Mono.empty();
}
```

If we want to protect specific endpoint's of our service or endpoints of specific HTTP requests types(GET, PUT etc), we can do so by creating a bean of type  
SecurityWebFilterChain like we have in WebFluxSecurityConfiguration. Below is an example of it which is self explanatory.

```
@Bean
public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

    http.authorizeExchange((exchanges) ->
            exchanges
                    .pathMatchers(HttpMethod.GET,"/greeting/**").hasAuthority("SCOPE_read:greeting")
                    .pathMatchers(HttpMethod.PUT, "/update-greeting/**").hasAuthority("SCOPE_write:greeting")
                    .anyExchange().authenticated()
    ).httpBasic(withDefaults())
     .formLogin(withDefaults());

    return http.build();

}
```

The intent of this write-up was do to explain default interfaces that are core part of spring security and also how to how to customize them.