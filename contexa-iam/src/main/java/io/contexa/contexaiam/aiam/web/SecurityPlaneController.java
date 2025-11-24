package io.contexa.contexaiam.aiam.web;

import lombok.RequiredArgsConstructor;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@RequiredArgsConstructor
public class SecurityPlaneController {

    @GetMapping("/admin/security-plane")
    public String soarAnalysis(Model model) {
        model.addAttribute("activePage", "soar-alAnalysis");
        return "admin/security-plane";
    }
}