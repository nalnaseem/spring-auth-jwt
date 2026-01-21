package com.alnaseem.jwt.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Simple controller exposing public and authenticated test endpoints used for quick health checks
 * and to verify that authentication is working as expected.
 */
@RestController
public class TestController {
    @GetMapping("/test")
    public String test() {
        return "test";
    }

    @GetMapping("/auth/test")
    public String authTest() {
        return "you are authenticated";
    }
}
