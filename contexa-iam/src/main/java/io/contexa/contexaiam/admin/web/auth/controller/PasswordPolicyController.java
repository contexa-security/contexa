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
import io.contexa.contexaiam.common.ConsoleFault;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/password-policy")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
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

    public String updatePolicy(PasswordPolicyForm policy, RedirectAttributes ra) {
        return updatePolicy(policy, null, ra);
    }

    /**
     * A value that is not a whole number, or one too large for one, is refused with the value it is about, as a value out
     * of range is: neither is a fault of the console.
     */
    @PostMapping
    public String updatePolicy(@ModelAttribute PasswordPolicyForm policy, @Nullable BindingResult binding,
                               RedirectAttributes ra) {
        if (binding != null && binding.hasFieldErrors()) {
            String field = binding.getFieldErrors().get(0).getField();
            String refusal = PasswordPolicyService.Bound.of(field)
                    .map(bound -> msg("admin.password.policy.refused.range", msg(bound.labelKey()), bound.min(), bound.max()))
                    .orElseGet(() -> msg("admin.password.policy.refused.value", field));
            log.warn("[PasswordPolicy] A policy was refused: field={} is not a value it may take", field);
            ra.addFlashAttribute("errorMessage", msg("msg.password.policy.update.error", refusal));
            return "redirect:/contexa/admin/password-policy";
        }
        try {
            passwordPolicyService.updatePolicy(policy.toPasswordPolicy());
            ra.addFlashAttribute("message", msg("msg.password.policy.updated"));
        } catch (PasswordPolicyService.PolicyRefusedException refused) {
            log.warn("[PasswordPolicy] A policy was refused: {}", refused.getMessage());
            ra.addFlashAttribute("errorMessage", msg("msg.password.policy.update.error", refusalText(refused)));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.password.policy.update.error",
                    ConsoleFault.textOf(e, log, "update the password policy")));
        }
        return "redirect:/contexa/admin/password-policy";
    }

    private String refusalText(PasswordPolicyService.PolicyRefusedException refused) {
        List<Object> args = new ArrayList<>();
        if (refused.getLabelKey() != null) {
            args.add(msg(refused.getLabelKey()));
        }
        args.addAll(Arrays.asList(refused.getMessageArgs()));
        return msg(refused.getMessageKey(), args.toArray());
    }

    @GetMapping("/api/rules")
    @ResponseBody
    public ResponseEntity<PasswordPolicyRulesResponse> getPolicyRules() {
        return ResponseEntity.ok(PasswordPolicyRulesResponse.from(passwordPolicyService.getCurrentPolicy()));
    }
}
