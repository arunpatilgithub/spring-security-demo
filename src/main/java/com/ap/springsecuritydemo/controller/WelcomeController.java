package com.ap.springsecuritydemo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
public class WelcomeController {

    @GetMapping("/hello")
    public Mono<String> greet() {

        log.info("Rest service called!");
        return Mono.just("Hello World!");
    }

}
