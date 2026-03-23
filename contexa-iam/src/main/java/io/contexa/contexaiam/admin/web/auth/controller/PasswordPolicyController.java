package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/admin/password-policy")
@RequiredArgsConstructor
public class PasswordPolicyController {

    private final PasswordPolicyService passwordPolicyService;

    @GetMapping
    public String showPolicy(Model model) {
        model.addAttribute("policy", passwordPolicyService.getCurrentPolicy());
        model.addAttribute("activePage", "password-policy");
        return "admin/password-policy";
    }

    @PostMapping
    public String updatePolicy(@ModelAttribute PasswordPolicy policy, RedirectAttributes ra) {
        try {
            passwordPolicyService.updatePolicy(policy);
            ra.addFlashAttribute("message", "Password policy updated successfully.");
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", "Failed to update password policy: " + e.getMessage());
        }
        return "redirect:/admin/password-policy";
    }
}
