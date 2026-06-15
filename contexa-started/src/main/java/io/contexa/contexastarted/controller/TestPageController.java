package io.contexa.contexastarted.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves Thymeleaf test pages for the @Protectable example.
 */
@Controller
public class TestPageController {

    @GetMapping("/")
    public String protectableTestPage() {
        return "test/protectable-test";
    }
}
