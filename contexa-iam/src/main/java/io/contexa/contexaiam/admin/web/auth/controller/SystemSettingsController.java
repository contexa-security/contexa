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

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/system-settings")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class SystemSettingsController {

    private final SystemSettingsService systemSettingsService;
    private final PolicyCombiningProperties policyCombiningProperties;
    private final MessageSource messageSource;
    @Nullable
    private final CustomDynamicAuthorizationManager authorizationManager;
    @Nullable
    private final SystemSettingsRuntimeApplier runtimeApplier;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String showSettings(Model model) {
        model.addAttribute("activePage", "system-settings");
        model.addAttribute("settings", SystemSettingsForm.from(systemSettingsService.getSettings()));
        model.addAttribute("roles", systemSettingsService.getDefaultRoleOptions());
        model.addAttribute("algorithms", CombiningAlgorithm.values());
        model.addAttribute("zeroTrustModeOptions", SecurityZeroTrustProperties.SecurityMode.values());
        return "contexa/admin/system-settings";
    }

    @PostMapping
    public String updateSettings(@ModelAttribute("settings") SystemSettingsForm form,
                                 RedirectAttributes ra) {
        try {
            systemSettingsService.updateSettings(form);

            if (runtimeApplier != null) {
                runtimeApplier.apply();
            }

            // Apply combining-algorithm change at runtime so subsequent authorization decisions use it
            // immediately on this JVM instance. (Distributed propagation is tracked separately.)
            if (authorizationManager != null) {
                try {
                    CombiningAlgorithm algorithm = CombiningAlgorithm.valueOf(form.getPolicyCombiningAlgorithm());
                    policyCombiningProperties.setCombiningAlgorithm(algorithm);
                    authorizationManager.setCombiningAlgorithm(algorithm);
                    authorizationManager.reload();
                } catch (IllegalArgumentException e) {
                    log.error("Invalid combining algorithm: {}", form.getPolicyCombiningAlgorithm());
                }
            }

            ra.addFlashAttribute("message", msg("admin.system.settings.saved"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage",
                    msg("admin.system.settings.save.failed") + ": " + e.getMessage());
        }
        return "redirect:/contexa/admin/system-settings";
    }
}
