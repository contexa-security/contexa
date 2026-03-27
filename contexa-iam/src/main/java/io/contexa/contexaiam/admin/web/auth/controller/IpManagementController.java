package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.common.CsvColumn;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.domain.entity.IpAccessRule;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Slf4j
@Controller
@RequestMapping("/admin/ip-management")
@RequiredArgsConstructor
public class IpManagementController {

    private static final int PAGE_SIZE = 20;
    private static final DateTimeFormatter CSV_TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final IpAccessRuleService ipAccessRuleService;
    private final MessageSource messageSource;
    private final CsvExportService csvExportService;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String list(@RequestParam(required = false) String type,
                       @RequestParam(defaultValue = "0") int page,
                       Model model) {
        PageRequest pageable = PageRequest.of(page, PAGE_SIZE);

        Page<IpAccessRule> rules;
        if ("ALLOW".equalsIgnoreCase(type)) {
            rules = ipAccessRuleService.getRulesByType(IpAccessRule.RuleType.ALLOW, pageable);
        } else if ("DENY".equalsIgnoreCase(type)) {
            rules = ipAccessRuleService.getRulesByType(IpAccessRule.RuleType.DENY, pageable);
        } else {
            rules = ipAccessRuleService.getAllRules(pageable);
            type = null;
        }

        model.addAttribute("rules", rules);
        model.addAttribute("currentType", type);
        model.addAttribute("allowCount", ipAccessRuleService.countAllowRules());
        model.addAttribute("denyCount", ipAccessRuleService.countDenyRules());
        model.addAttribute("totalCount", ipAccessRuleService.countAllowRules() + ipAccessRuleService.countDenyRules());
        return "admin/ip-management";
    }

    @PostMapping("/create")
    public String createRule(@RequestParam String ipAddress,
                             @RequestParam String ruleType,
                             @RequestParam(required = false) String description,
                             @RequestParam(required = false) String expiresAt,
                             RedirectAttributes ra) {
        if (!ipAccessRuleService.isValidIpOrCidr(ipAddress)) {
            ra.addFlashAttribute("errorMessage", msg("admin.ip.invalid.ip"));
            return "redirect:/admin/ip-management";
        }

        IpAccessRule.RuleType type;
        try {
            type = IpAccessRule.RuleType.valueOf(ruleType.toUpperCase());
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", msg("admin.ip.invalid.ip"));
            return "redirect:/admin/ip-management";
        }

        if (ipAccessRuleService.existsByIpAndType(ipAddress.trim(), type)) {
            ra.addFlashAttribute("errorMessage", msg("admin.ip.duplicate"));
            return "redirect:/admin/ip-management";
        }

        LocalDateTime expires = null;
        if (expiresAt != null && !expiresAt.isBlank()) {
            try {
                expires = LocalDateTime.parse(expiresAt);
            } catch (Exception e) {
                log.error("Invalid expiresAt format: {}", expiresAt, e);
            }
        }

        String createdBy = extractCurrentUserId();
        ipAccessRuleService.createRule(ipAddress.trim(), type, description, createdBy, expires);
        ra.addFlashAttribute("message", msg("admin.ip.created"));
        return "redirect:/admin/ip-management";
    }

    @PostMapping("/{id}/delete")
    public String deleteRule(@PathVariable Long id, RedirectAttributes ra) {
        try {
            ipAccessRuleService.deleteRule(id);
            ra.addFlashAttribute("message", msg("admin.ip.deleted"));
        } catch (Exception e) {
            log.error("Failed to delete IP rule: id={}", id, e);
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/ip-management";
    }

    @PostMapping("/{id}/toggle")
    public String toggleRule(@PathVariable Long id, RedirectAttributes ra) {
        try {
            ipAccessRuleService.toggleRule(id);
            ra.addFlashAttribute("message", msg("admin.ip.toggled"));
        } catch (Exception e) {
            log.error("Failed to toggle IP rule: id={}", id, e);
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/ip-management";
    }

    @GetMapping("/export")
    public void export(@RequestParam(required = false) String type,
                       HttpServletResponse response) throws IOException {
        List<CsvColumn<IpAccessRule>> columns = List.of(
                new CsvColumn<>("IP Address", r -> r.getIpAddress() != null ? r.getIpAddress() : ""),
                new CsvColumn<>("Rule Type", r -> r.getRuleType() != null ? r.getRuleType().name() : ""),
                new CsvColumn<>("Description", r -> r.getDescription() != null ? r.getDescription() : ""),
                new CsvColumn<>("Created By", r -> r.getCreatedBy() != null ? r.getCreatedBy() : ""),
                new CsvColumn<>("Created At", r -> r.getCreatedAt() != null ? r.getCreatedAt().format(CSV_TS) : ""),
                new CsvColumn<>("Expires At", r -> r.getExpiresAt() != null ? r.getExpiresAt().format(CSV_TS) : ""),
                new CsvColumn<>("Enabled", r -> String.valueOf(r.isEnabled()))
        );

        csvExportService.export(response, "ip-access-rules", columns, () -> {
            if ("ALLOW".equalsIgnoreCase(type)) {
                return ipAccessRuleService.findAllEnabledRules().stream()
                        .filter(r -> r.getRuleType() == IpAccessRule.RuleType.ALLOW);
            } else if ("DENY".equalsIgnoreCase(type)) {
                return ipAccessRuleService.findAllEnabledRules().stream()
                        .filter(r -> r.getRuleType() == IpAccessRule.RuleType.DENY);
            }
            return ipAccessRuleService.findAllEnabledRules().stream();
        });
    }

    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        return "unknown";
    }
}
