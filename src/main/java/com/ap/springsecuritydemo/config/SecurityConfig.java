package com.ap.springsecuritydemo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {

    //Override AuthenticationManager
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

    //We can override UserDetailsService too instead of AuthenticationManager.
    //@Bean
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

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.csrf(c -> c.disable()).authorizeExchange(exchanges -> exchanges
                        .anyExchange().authenticated()
                )
                .httpBasic(withDefaults())
                .formLogin(withDefaults());

        return http.build();
    }



}
