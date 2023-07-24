package com.ap.springsecuritydemo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
public class WelcomeController {

    @GetMapping("/greeting")
    public Mono<String> greeting() {

        return Mono.just("Hello World!");
    }

    @PutMapping("/update-greeting/{user}")
    public Mono<String> updateGreeting(@PathVariable String user) {
        return Mono.just("Hello World!" + user);
    }

}
