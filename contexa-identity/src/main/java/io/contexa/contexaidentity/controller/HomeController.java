package io.contexa.contexaidentity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/authMode")
    public String authMode() {
        return "auth-mode";
    }
}
