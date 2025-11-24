package io.contexa.contexaiam.admin.web.auth.controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

public class LoginController {

    @GetMapping("/login")
    public String registerPage(Model model) {
        return "admin/login";
    }

}
