package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexacommon.entity.SystemSettings;
import io.contexa.contexaiam.admin.web.auth.service.SystemSettingsService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Slf4j
@Controller
@RequestMapping("/admin/system-settings")
@RequiredArgsConstructor
public class SystemSettingsController {

    private final SystemSettingsService systemSettingsService;
    private final MessageSource messageSource;
    @Nullable
    private final CustomDynamicAuthorizationManager authorizationManager;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String showSettings(Model model) {
        model.addAttribute("activePage", "system-settings");
        model.addAttribute("settings", systemSettingsService.getSettings());
        return "admin/system-settings";
    }

    @PostMapping
    public String updateSettings(@ModelAttribute SystemSettings settings, RedirectAttributes ra) {
        try {
            systemSettingsService.updateSettings(settings);

            // Apply combining algorithm change at runtime
            if (authorizationManager != null) {
                try {
                    CombiningAlgorithm algorithm = CombiningAlgorithm.valueOf(settings.getPolicyCombiningAlgorithm());
                    authorizationManager.setCombiningAlgorithm(algorithm);
                    authorizationManager.reload();
                } catch (IllegalArgumentException e) {
                    log.error("Invalid combining algorithm: {}", settings.getPolicyCombiningAlgorithm());
                }
            }

            ra.addFlashAttribute("message", msg("admin.system.settings.saved"));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("admin.system.settings.save.failed") + ": " + e.getMessage());
        }
        return "redirect:/admin/system-settings";
    }
}
