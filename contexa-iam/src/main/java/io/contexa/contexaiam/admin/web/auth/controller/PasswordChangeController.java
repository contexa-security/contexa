/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.PasswordChangeService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class PasswordChangeController {

    private final PasswordChangeService passwordChangeService;
    private final PasswordPolicyService passwordPolicyService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping("/contexa/password-change")
    public String showPasswordChangeForm(@RequestParam String username, Model model) {
        model.addAttribute("username", username);
        model.addAttribute("policy", passwordPolicyService.getCurrentPolicy());
        return "contexa/password-change";
    }

    @PostMapping("/contexa/password-change")
    public String processPasswordChange(
            @RequestParam String username,
            @RequestParam String currentPassword,
            @RequestParam String newPassword,
            @RequestParam String confirmPassword,
            RedirectAttributes ra) {
        try {
            passwordChangeService.changePassword(username, currentPassword, newPassword, confirmPassword);
        } catch (PasswordChangeService.PasswordChangeException e) {
            ra.addFlashAttribute("errorMessage", msg(e.getMessageKey(), e.getMessageArgs()));
            return "redirect:/contexa/password-change?username=" + username;
        }

        ra.addFlashAttribute("message", msg("msg.password.change.success"));
        return "redirect:/contexa/admin/mfa/login";
    }
}