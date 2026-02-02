package io.contexa.contexaiam.admin.web.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/admin/login")
    public String registerPage(Model model) {
        return "admin/login";
    }

}
