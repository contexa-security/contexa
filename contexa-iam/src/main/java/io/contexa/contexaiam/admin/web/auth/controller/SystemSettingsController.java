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
import io.contexa.contexaiam.common.ConsoleFault;
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
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/system-settings")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
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

    /**
     * Runtime zero trust settings whose mode is shown when no mode is stored.
     */
    @Setter
    @Nullable
    private SecurityZeroTrustProperties zeroTrustProperties;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String showSettings(Model model) {
        model.addAttribute("activePage", "system-settings");
        model.addAttribute("settings", SystemSettingsForm.from(systemSettingsService.getSettings(),
                zeroTrustProperties != null ? zeroTrustProperties.getMode() : null,
                policyCombiningProperties.getNoMatchingUrlPolicyDecision()));
        model.addAttribute("roles", systemSettingsService.getDefaultRoleOptions());
        model.addAttribute("algorithms", CombiningAlgorithm.values());
        model.addAttribute("noMatchingUrlPolicyDecisionOptions", NoPolicyDecision.values());
        model.addAttribute("noPolicyDecisionOptions", SystemRuntimeSettingsService.missingMethodPolicyDecisionOptions());
        model.addAttribute("zeroTrustModeOptions", SecurityZeroTrustProperties.EnforcementMode.values());
        return "contexa/admin/system-settings";
    }

    public String updateSettings(SystemSettingsForm form, RedirectAttributes ra) {
        return updateSettings(form, null, ra);
    }

    /**
     * A value that is not a number is refused with the value it is about, as a value out of range is; neither is a
     * fault of the console. A refusal names the value in the administrator's language.
     */
    @PostMapping
    public String updateSettings(@ModelAttribute("settings") SystemSettingsForm form, @Nullable BindingResult binding,
                                 RedirectAttributes ra) {
        if (binding != null && binding.hasFieldErrors()) {
            String field = binding.getFieldErrors().get(0).getField();
            String refusal = Arrays.stream(SystemSettingsService.Bound.values())
                    .filter(bound -> bound.field().equals(field))
                    .findFirst()
                    .map(bound -> msg("admin.system.settings.refused.range", msg(bound.labelKey()), bound.min(), bound.max()))
                    .orElseGet(() -> msg("admin.system.settings.refused.choice", field, String.valueOf(
                            binding.getFieldErrors().get(0).getRejectedValue())));
            log.warn("[SystemSettings] Settings were refused: field={} is not a value it may take", field);
            ra.addFlashAttribute("errorMessage", msg("admin.system.settings.save.failed") + ": " + refusal);
            return "redirect:/contexa/admin/system-settings";
        }
        try {
            systemSettingsService.updateSettings(form);
            applyRuntimeSettings(form);
            ra.addFlashAttribute("message", msg("admin.system.settings.saved"));
        } catch (SystemSettingsService.SettingRefusedException refused) {
            log.warn("[SystemSettings] Settings were refused: {}", refused.getMessage());
            List<Object> args = new ArrayList<>();
            if (refused.getLabelKey() != null) {
                args.add(msg(refused.getLabelKey()));
            }
            args.addAll(Arrays.asList(refused.getMessageArgs()));
            ra.addFlashAttribute("errorMessage", msg("admin.system.settings.save.failed") + ": "
                    + msg(refused.getMessageKey(), args.toArray()));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage",
                    msg("admin.system.settings.save.failed") + ": "
                            + ConsoleFault.textOf(e, log, "save the system settings"));
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
                            // a form that names no decision chose none: the one in effect stays
                            StringUtils.hasText(form.getNoMatchingUrlPolicyDecision())
                                    ? SystemRuntimeSettingsService.parseNoPolicyDecision(
                                    "noMatchingUrlPolicyDecision", form.getNoMatchingUrlPolicyDecision())
                                    : null,
                            SystemRuntimeSettingsService.parseMissingMethodPolicyDecision(
                                    form.getMissingMethodPolicyDecision())));
        }
        if (authorizationManager != null) {
            authorizationManager.reload();
        }
        if (policyReloadBroadcaster != null) {
            policyReloadBroadcaster.broadcastReload();
        }
    }
}
