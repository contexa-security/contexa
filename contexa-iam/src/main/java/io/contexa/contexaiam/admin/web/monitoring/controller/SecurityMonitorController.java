package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Security Monitor - real-time security event viewer based on audit_log.
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
        List<AuditLog> allLogs = auditLogRepository.findByCreatedAtAfter(since);

        // Filter by dashboard drill-down filter or category
        List<AuditLog> filtered = allLogs;
        if (filter != null && !filter.isBlank()) {
            model.addAttribute("filterType", filter);
            filtered = switch (filter) {
                case "AFTER_HOURS" -> allLogs.stream()
                        .filter(log -> {
                            if (log.getTimestamp() == null) return false;
                            int hour = log.getTimestamp().getHour();
                            int dow = log.getTimestamp().getDayOfWeek().getValue();
                            return hour < 9 || hour >= 18 || dow >= 6;
                        }).toList();
                case "DISTINCT_IP" -> allLogs.stream()
                        .filter(log -> log.getClientIp() != null && !log.getClientIp().isBlank())
                        .toList();
                case "HIGH_RISK" -> allLogs.stream()
                        .filter(log -> log.getRiskScore() != null && log.getRiskScore() >= 0.4)
                        .toList();
                case "DECISION_ALLOW" -> allLogs.stream()
                        .filter(log -> "ALLOW".equals(log.getDecision()))
                        .toList();
                case "DECISION_DENY" -> allLogs.stream()
                        .filter(log -> "DENY".equals(log.getDecision()) || "BLOCK".equals(log.getDecision()))
                        .toList();
                default -> allLogs.stream()
                        .filter(log -> filter.equals(log.getEventCategory()))
                        .toList();
            };
        } else if (category != null && !category.isBlank()) {
            filtered = allLogs.stream()
                    .filter(log -> category.equals(log.getEventCategory()))
                    .toList();
        }

        // Paginate
        int pageSize = 20;
        int start = Math.min(page * pageSize, filtered.size());
        int end = Math.min(start + pageSize, filtered.size());
        List<AuditLog> pageContent = filtered.subList(start, end);

        Pageable pageable = PageRequest.of(page, pageSize);
        Page<AuditLog> logPage = new PageImpl<>(pageContent, pageable, filtered.size());

        // Summary counts
        long allowCount = allLogs.stream().filter(l -> "ALLOW".equals(l.getDecision())).count();
        long denyCount = allLogs.stream().filter(l -> "DENY".equals(l.getDecision())).count();
        long authSuccess = allLogs.stream().filter(l -> "AUTHENTICATION_SUCCESS".equals(l.getEventCategory())).count();
        long authFailure = allLogs.stream().filter(l -> "AUTHENTICATION_FAILURE".equals(l.getEventCategory())).count();
        long securityDecision = allLogs.stream().filter(l -> "SECURITY_DECISION".equals(l.getEventCategory())).count();
        long adminOverride = allLogs.stream().filter(l -> "ADMIN_OVERRIDE".equals(l.getEventCategory())).count();

        // IP grouping for DISTINCT_IP filter
        if ("DISTINCT_IP".equals(filter)) {
            Map<String, List<AuditLog>> ipGroups = filtered.stream()
                    .collect(Collectors.groupingBy(
                            l -> l.getClientIp() != null ? l.getClientIp() : "unknown",
                            LinkedHashMap::new,
                            Collectors.toList()));
            model.addAttribute("ipGroups", ipGroups);
        }

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
        model.addAttribute("totalCount", (long) allLogs.size());

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
