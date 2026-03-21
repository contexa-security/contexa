package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Security Monitor - real-time security event viewer based on audit_log.
 * All queries use DB-level pagination to handle millions of records.
 */
@Controller
@RequestMapping("/admin/security-monitor")
@RequiredArgsConstructor
@Slf4j
public class SecurityMonitorController {

    private final AuditLogRepository auditLogRepository;

    @GetMapping
    public String monitor(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false, defaultValue = "24") int hours,
            @RequestParam(required = false, defaultValue = "0") int page,
            Model model) {

        model.addAttribute("activePage", "security-monitor");

        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        int pageSize = 20;
        Pageable pageable = PageRequest.of(page, pageSize, Sort.by(Sort.Direction.DESC, "timestamp"));

        // DB-level paginated query based on filter type
        Page<AuditLog> logPage;
        if (filter != null && !filter.isBlank()) {
            model.addAttribute("filterType", filter);
            logPage = switch (filter) {
                case "AFTER_HOURS" -> auditLogRepository.findAfterHoursAccess(since, PageRequest.of(page, pageSize));
                case "DISTINCT_IP" -> auditLogRepository.findByTimestampAfterAndClientIpNotNull(since, pageable);
                case "HIGH_RISK" -> auditLogRepository.findByTimestampAfterAndRiskScoreGte(since, 0.4, pageable);
                case "DECISION_ALLOW" -> auditLogRepository.findByTimestampAfterAndDecision(since, "ALLOW", pageable);
                case "DECISION_DENY" -> auditLogRepository.findByTimestampAfterAndDecision(since, "DENY", pageable);
                default -> auditLogRepository.findByTimestampAfterAndCategory(since, filter, pageable);
            };

            // IP grouping for DISTINCT_IP filter (paginated, max 20 IPs per page)
            if ("DISTINCT_IP".equals(filter)) {
                int ipPage = page;
                int ipSize = 20;
                List<Object[]> ipRows = auditLogRepository.findIpGroupsSince(since, ipSize, ipPage * ipSize);
                long totalIpGroups = auditLogRepository.countDistinctIpGroupsSince(since);

                List<Map<String, Object>> ipGroups = new ArrayList<>();
                for (Object[] row : ipRows) {
                    Map<String, Object> group = new LinkedHashMap<>();
                    group.put("ip", row[0]);
                    group.put("count", ((Number) row[1]).longValue());
                    group.put("lastAccess", row[2]);
                    ipGroups.add(group);
                }
                model.addAttribute("ipGroups", ipGroups);
                model.addAttribute("totalIpGroups", totalIpGroups);
            }
        } else if (category != null && !category.isBlank()) {
            logPage = auditLogRepository.findByTimestampAfterAndCategory(since, category, pageable);
        } else {
            logPage = auditLogRepository.findByTimestampAfter(since, pageable);
        }

        // Summary counts (DB-level aggregate, no full load)
        long totalCount = auditLogRepository.countByTimestampAfter(since);
        long allowCount = auditLogRepository.countAllowedSince(since);
        long denyCount = auditLogRepository.countDeniedSince(since);
        long authSuccess = auditLogRepository.countByEventCategoryAndTimestampAfter("AUTHENTICATION_SUCCESS", since);
        long authFailure = auditLogRepository.countByEventCategoryAndTimestampAfter("AUTHENTICATION_FAILURE", since);
        long securityDecision = auditLogRepository.countByEventCategoryAndTimestampAfter("SECURITY_DECISION", since);
        long adminOverride = auditLogRepository.countAdminOverridesSince(since);

        model.addAttribute("logPage", logPage);
        model.addAttribute("hours", hours);
        model.addAttribute("category", category);
        model.addAttribute("filter", filter);
        model.addAttribute("allowCount", allowCount);
        model.addAttribute("denyCount", denyCount);
        model.addAttribute("authSuccess", authSuccess);
        model.addAttribute("authFailure", authFailure);
        model.addAttribute("securityDecision", securityDecision);
        model.addAttribute("adminOverride", adminOverride);
        model.addAttribute("totalCount", totalCount);

        return "admin/security-monitor";
    }

    @GetMapping("/{id}")
    public String detail(@PathVariable Long id, Model model) {
        model.addAttribute("activePage", "security-monitor");

        AuditLog auditLog = auditLogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Audit log not found: " + id));

        model.addAttribute("log", auditLog);
        return "admin/security-monitor-detail";
    }
}
