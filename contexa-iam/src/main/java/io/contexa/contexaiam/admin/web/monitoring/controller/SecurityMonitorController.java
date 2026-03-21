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
import java.util.List;

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
            @RequestParam(required = false, defaultValue = "24") int hours,
            @RequestParam(required = false, defaultValue = "0") int page,
            Model model) {

        model.addAttribute("activePage", "security-monitor");

        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        List<AuditLog> allLogs = auditLogRepository.findByCreatedAtAfter(since);

        // Filter by category if specified
        List<AuditLog> filtered = allLogs;
        if (category != null && !category.isBlank()) {
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

        model.addAttribute("logPage", logPage);
        model.addAttribute("hours", hours);
        model.addAttribute("category", category);
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
