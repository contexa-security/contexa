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

import io.contexa.contexaiam.admin.web.auth.dto.PasswordPolicyDtos.PasswordPolicyForm;
import io.contexa.contexaiam.admin.web.auth.dto.PasswordPolicyDtos.PasswordPolicyRulesResponse;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/contexa/admin/password-policy")
@RequiredArgsConstructor
public class PasswordPolicyController {

    private final PasswordPolicyService passwordPolicyService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String showPolicy(Model model) {
        model.addAttribute("policy", PasswordPolicyForm.from(passwordPolicyService.getCurrentPolicy()));
        model.addAttribute("activePage", "password-policy");
        return "contexa/admin/password-policy";
    }

    @PostMapping
    public String updatePolicy(@ModelAttribute PasswordPolicyForm policy, RedirectAttributes ra) {
        try {
            passwordPolicyService.updatePolicy(policy.toPasswordPolicy());
            ra.addFlashAttribute("message", msg("msg.password.policy.updated"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.password.policy.update.error", e.getMessage()));
        }
        return "redirect:/contexa/admin/password-policy";
    }

    @GetMapping("/api/rules")
    @ResponseBody
    public ResponseEntity<PasswordPolicyRulesResponse> getPolicyRules() {
        return ResponseEntity.ok(PasswordPolicyRulesResponse.from(passwordPolicyService.getCurrentPolicy()));
    }
}
