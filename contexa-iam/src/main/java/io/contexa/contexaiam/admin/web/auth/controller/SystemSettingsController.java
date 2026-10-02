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

import io.contexa.contexacore.infra.redis.PolicyReloadBroadcaster;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.admin.web.auth.dto.SystemSettingsDtos.SystemSettingsForm;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService.PolicyDecisionSettings;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsRuntimeApplier;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties.NoPolicyDecision;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
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

    @Setter
    @Nullable
    private PolicyReloadBroadcaster policyReloadBroadcaster;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String showSettings(Model model) {
        model.addAttribute("activePage", "system-settings");
        model.addAttribute("settings", SystemSettingsForm.from(systemSettingsService.getSettings()));
        model.addAttribute("roles", systemSettingsService.getDefaultRoleOptions());
        model.addAttribute("algorithms", CombiningAlgorithm.values());
        model.addAttribute("noPolicyDecisionOptions", NoPolicyDecision.values());
        model.addAttribute("zeroTrustModeOptions", SecurityZeroTrustProperties.SecurityMode.values());
        return "contexa/admin/system-settings";
    }

    @PostMapping
    public String updateSettings(@ModelAttribute("settings") SystemSettingsForm form,
                                 RedirectAttributes ra) {
        try {
            systemSettingsService.updateSettings(form);
            applyRuntimeSettings(form);
            ra.addFlashAttribute("message", msg("admin.system.settings.saved"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage",
                    msg("admin.system.settings.save.failed") + ": " + e.getMessage());
        }
        return "redirect:/contexa/admin/system-settings";
    }

    /**
     * Applies the saved settings to this JVM, rebuilds the URL policy mappings and asks the other
     * instances to re-read the stored settings and reload.
     */
    private void applyRuntimeSettings(SystemSettingsForm form) {
        if (runtimeApplier != null) {
            runtimeApplier.apply();
        } else {
            SystemSettingsRuntimeApplier.applyPolicyDecisionSettings(policyCombiningProperties, authorizationManager,
                    new PolicyDecisionSettings(
                            SystemRuntimeSettingsService.parseCombiningAlgorithm(form.getPolicyCombiningAlgorithm()),
                            SystemRuntimeSettingsService.parseNoPolicyDecision(
                                    "noMatchingUrlPolicyDecision", form.getNoMatchingUrlPolicyDecision()),
                            SystemRuntimeSettingsService.parseNoPolicyDecision(
                                    "missingMethodPolicyDecision", form.getMissingMethodPolicyDecision())));
        }
        if (authorizationManager != null) {
            authorizationManager.reload();
        }
        if (policyReloadBroadcaster != null) {
            policyReloadBroadcaster.broadcastReload();
        }
    }
}
