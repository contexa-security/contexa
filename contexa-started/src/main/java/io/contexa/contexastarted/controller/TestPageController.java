package io.contexa.contexastarted.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TestPageController {

    @GetMapping("/")
    public String protectableTestPage() {
        return "redirect:/contexa/admin/ai-monitor";
    }
}
