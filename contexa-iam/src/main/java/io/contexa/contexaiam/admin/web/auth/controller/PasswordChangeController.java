package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class PasswordChangeController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping("/password-change")
    public String showPasswordChangeForm(@RequestParam String username, Model model) {
        model.addAttribute("username", username);
        model.addAttribute("policy", passwordPolicyService.getCurrentPolicy());
        return "password-change";
    }

    @PostMapping("/password-change")
    @Transactional
    @CacheEvict(value = "usersWithAuthorities", allEntries = true)
    public String processPasswordChange(
            @RequestParam String username,
            @RequestParam String currentPassword,
            @RequestParam String newPassword,
            @RequestParam String confirmPassword,
            RedirectAttributes ra) {

        // Validate user exists
        Users user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            ra.addFlashAttribute("errorMessage", msg("msg.password.change.user.not.found"));
            return "redirect:/password-change?username=" + username;
        }

        // Validate current password
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            ra.addFlashAttribute("errorMessage", msg("msg.password.change.current.incorrect"));
            return "redirect:/password-change?username=" + username;
        }

        // Validate new password confirmation
        if (!newPassword.equals(confirmPassword)) {
            ra.addFlashAttribute("errorMessage", msg("msg.password.change.mismatch"));
            return "redirect:/password-change?username=" + username;
        }

        // Validate against password policy
        List<String> violations = passwordPolicyService.validatePassword(newPassword);
        if (!violations.isEmpty()) {
            ra.addFlashAttribute("errorMessage", msg("msg.password.change.policy.violation", String.join(", ", violations)));
            return "redirect:/password-change?username=" + username;
        }

        // Save new password
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setCredentialsExpired(false);
        userRepository.save(user);

        ra.addFlashAttribute("message", msg("msg.password.change.success"));
        return "redirect:/admin/mfa/login";
    }
}
