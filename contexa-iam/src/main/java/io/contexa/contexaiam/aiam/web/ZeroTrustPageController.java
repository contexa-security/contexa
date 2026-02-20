package io.contexa.contexaiam.aiam.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Page controller serving Zero Trust BLOCK/ESCALATE dedicated pages.
 */
@Controller
@RequestMapping("/zero-trust")
public class ZeroTrustPageController {

    @GetMapping("/blocked")
    public String blocked() {
        return "zero-trust/blocked";
    }

    @GetMapping("/analysis-pending")
    public String analysisPending(
            @RequestParam(required = false, defaultValue = "/") String returnUrl,
            Model model) {
        model.addAttribute("returnUrl", returnUrl);
        return "zero-trust/analysis-pending";
    }
}
