package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.PasswordPolicy;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.LinkedHashMap;
import java.util.Map;

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

    @GetMapping("/api/rules")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getPolicyRules() {
        PasswordPolicy policy = passwordPolicyService.getCurrentPolicy();
        Map<String, Object> rules = new LinkedHashMap<>();
        rules.put("minLength", policy.getMinLength());
        rules.put("maxLength", policy.getMaxLength());
        rules.put("requireUppercase", policy.isRequireUppercase());
        rules.put("requireLowercase", policy.isRequireLowercase());
        rules.put("requireDigit", policy.isRequireDigit());
        rules.put("requireSpecialChar", policy.isRequireSpecialChar());
        return ResponseEntity.ok(rules);
    }
}
