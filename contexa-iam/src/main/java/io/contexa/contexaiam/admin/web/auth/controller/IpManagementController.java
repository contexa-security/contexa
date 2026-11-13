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

import io.contexa.contexacore.autonomous.utils.RequestInfoExtractor;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexaiam.common.ConsoleFault;
import java.util.Locale;
import io.contexa.contexaiam.admin.web.auth.service.IpAccessRuleService;
import io.contexa.contexaiam.admin.web.common.CsvColumn;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.domain.entity.IpAccessRule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/ip-management")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class IpManagementController {

    private static final int PAGE_SIZE = 20;
    private static final DateTimeFormatter CSV_TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final IpAccessRuleService ipAccessRuleService;
    private final MessageSource messageSource;
    private final CsvExportService csvExportService;
    private final TieredStrategyProperties.Security securityProperties;

    public IpManagementController(IpAccessRuleService ipAccessRuleService, MessageSource messageSource,
                                  CsvExportService csvExportService) {
        this(ipAccessRuleService, messageSource, csvExportService, null);
    }

    /**
     * @param securityProperties how the IP access filter reads the address of a request (the proxies it trusts), so
     *                           that a change is checked against the address the filter will see; null for the defaults
     */
    public IpManagementController(IpAccessRuleService ipAccessRuleService, MessageSource messageSource,
                                  CsvExportService csvExportService,
                                  TieredStrategyProperties.Security securityProperties) {
        this.ipAccessRuleService = ipAccessRuleService;
        this.messageSource = messageSource;
        this.csvExportService = csvExportService;
        this.securityProperties = securityProperties != null ? securityProperties : new TieredStrategyProperties.Security();
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String list(@RequestParam(required = false) String type,
                       @RequestParam(required = false) String keyword,
                       @RequestParam(defaultValue = "0") int page,
                       Model model) {
        model.addAttribute("activePage", "ip-management");
        // A page number below the first is the first page, as in every other list of the console.
        PageRequest pageable = PageRequest.of(Math.max(page, 0), PAGE_SIZE);

        Page<IpAccessRule> rules = ipAccessRuleService.searchRules(type, keyword, pageable);
        String currentType = ipAccessRuleService.normalizeRuleTypeFilter(type);

        model.addAttribute("rules", rules);
        model.addAttribute("currentType", currentType);
        model.addAttribute("keyword", keyword);
        model.addAttribute("allowCount", ipAccessRuleService.countAllowRules());
        model.addAttribute("denyCount", ipAccessRuleService.countDenyRules());
        model.addAttribute("totalCount", ipAccessRuleService.countAllowRules() + ipAccessRuleService.countDenyRules());
        return "contexa/admin/ip-management";
    }

    @PostMapping("/create")
    public String createRule(@RequestParam String ipAddress,
                             @RequestParam String ruleType,
                             @RequestParam(required = false) String description,
                             @RequestParam(required = false) String expiresAt,
                             HttpServletRequest request,
                             RedirectAttributes ra) {
        if (!ipAccessRuleService.isValidIpOrCidr(ipAddress)) {
            ra.addFlashAttribute("errorMessage", msg("admin.ip.invalid.ip"));
            return "redirect:/contexa/admin/ip-management";
        }

        IpAccessRule.RuleType type;
        try {
            type = IpAccessRule.RuleType.valueOf(ruleType.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", msg("admin.ip.invalid.type"));
            return "redirect:/contexa/admin/ip-management";
        }

        if (ipAccessRuleService.existsByIpAndType(ipAddress.trim(), type)) {
            ra.addFlashAttribute("errorMessage", msg("admin.ip.duplicate"));
            return "redirect:/contexa/admin/ip-management";
        }

        // A time that cannot be read is refused: taken as no time, a rule meant to end would be kept for ever.
        LocalDateTime expires = null;
        if (expiresAt != null && !expiresAt.isBlank()) {
            try {
                expires = LocalDateTime.parse(expiresAt.trim());
            } catch (DateTimeParseException e) {
                log.warn("[IpManagement] An IP rule was refused: the expiry {} is not a date and time", expiresAt);
                ra.addFlashAttribute("errorMessage", msg("admin.ip.invalid.expires"));
                return "redirect:/contexa/admin/ip-management";
            }
        }

        try {
            ipAccessRuleService.createRule(ipAddress.trim(), type, description, extractCurrentUserId(), expires,
                    clientIpOf(request));
            ra.addFlashAttribute("message", msg("admin.ip.created"));
        } catch (IpAccessRuleService.IpRuleRefusedException refused) {
            ra.addFlashAttribute("errorMessage", msg(refused.getMessageKey(), refused.getMessageArgs()));
        }
        return "redirect:/contexa/admin/ip-management";
    }

    @PostMapping("/{id}/delete")
    public String deleteRule(@PathVariable Long id, HttpServletRequest request, RedirectAttributes ra) {
        try {
            ipAccessRuleService.deleteRule(id, clientIpOf(request));
            ra.addFlashAttribute("message", msg("admin.ip.deleted"));
        } catch (IpAccessRuleService.IpRuleRefusedException refused) {
            ra.addFlashAttribute("errorMessage", msg("msg.ip.delete.error",
                    msg(refused.getMessageKey(), refused.getMessageArgs())));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.ip.delete.error",
                    ConsoleFault.textOf(e, log, "delete the IP rule " + id)));
        }
        return "redirect:/contexa/admin/ip-management";
    }

    @PostMapping("/{id}/toggle")
    public String toggleRule(@PathVariable Long id, HttpServletRequest request, RedirectAttributes ra) {
        try {
            ipAccessRuleService.toggleRule(id, clientIpOf(request));
            ra.addFlashAttribute("message", msg("admin.ip.toggled"));
        } catch (IpAccessRuleService.IpRuleRefusedException refused) {
            ra.addFlashAttribute("errorMessage", msg("msg.ip.toggle.error",
                    msg(refused.getMessageKey(), refused.getMessageArgs())));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.ip.toggle.error",
                    ConsoleFault.textOf(e, log, "turn the IP rule " + id + " on or off")));
        }
        return "redirect:/contexa/admin/ip-management";
    }

    /**
     * The rules the list shows: the same type and search word, so that the download is what the administrator sees.
     */
    @GetMapping("/export")
    public void export(@RequestParam(required = false) String type,
                       @RequestParam(required = false) String keyword,
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

        csvExportService.export(response, "ip-access-rules", columns,
                () -> ipAccessRuleService.searchRules(type, keyword, Pageable.unpaged()).stream());
    }

    /** The address the request comes from, read as the IP access filter reads it. */
    private String clientIpOf(HttpServletRequest request) {
        return request != null ? RequestInfoExtractor.extractClientIp(request, securityProperties) : null;
    }

    private String extractCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        return "unknown";
    }
}
