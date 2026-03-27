package io.contexa.contexaiam.admin.web.monitoring.controller;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.common.CsvColumn;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import jakarta.servlet.http.HttpServletResponse;
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

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

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
    private final CsvExportService csvExportService;

    @GetMapping
    public String monitor(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false, defaultValue = "24") int hours,
            @RequestParam(required = false, defaultValue = "0") int page,
            Model model) {

        model.addAttribute("activePage", "security-monitor");

        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        int pageSize = 20;
        Pageable pageable = PageRequest.of(page, pageSize, Sort.by(Sort.Direction.DESC, "timestamp"));

        boolean hasKeyword = keyword != null && !keyword.isBlank();
        String likePattern = hasKeyword ? "%" + keyword.trim().toLowerCase() + "%" : null;

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
                case "ZT_ALLOW" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "ALLOW", since, pageable);
                case "ZT_BLOCK" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "BLOCK", since, pageable);
                case "ZT_CHALLENGE" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "CHALLENGE", since, pageable);
                case "ZT_ESCALATE" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "ESCALATE", since, pageable);
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
        } else if (hasKeyword && category != null && !category.isBlank()) {
            logPage = auditLogRepository.findByTimestampAfterAndCategoryAndPrincipalNameLike(since, category, likePattern, pageable);
        } else if (hasKeyword) {
            logPage = auditLogRepository.findByTimestampAfterAndPrincipalNameLike(since, likePattern, pageable);
        } else if (category != null && !category.isBlank()) {
            logPage = auditLogRepository.findByTimestampAfterAndCategory(since, category, pageable);
        } else {
            logPage = auditLogRepository.findByTimestampAfter(since, pageable);
        }

        // Summary counts (DB-level aggregate, eventCategory-based)
        long totalCount = auditLogRepository.countByTimestampAfter(since);
        long authSuccess = auditLogRepository.countByEventCategoryAndTimestampAfter("AUTHENTICATION_SUCCESS", since);
        long authFailure = auditLogRepository.countByEventCategoryAndTimestampAfter("AUTHENTICATION_FAILURE", since);
        long securityDecision = auditLogRepository.countZeroTrustTotalSince(since);
        long userBlocked = auditLogRepository.countByEventCategoryAndTimestampAfter("USER_BLOCKED", since);
        long mfaVerified = auditLogRepository.countByEventCategoryAndTimestampAfter("MFA_VERIFICATION_SUCCESS", since);
        long adminOverride = auditLogRepository.countAdminOverridesSince(since);

        model.addAttribute("logPage", logPage);
        model.addAttribute("hours", hours);
        model.addAttribute("category", category);
        model.addAttribute("filter", filter);
        model.addAttribute("keyword", keyword);
        model.addAttribute("totalCount", totalCount);
        model.addAttribute("authSuccess", authSuccess);
        model.addAttribute("authFailure", authFailure);
        model.addAttribute("securityDecision", securityDecision);
        model.addAttribute("userBlocked", userBlocked);
        model.addAttribute("mfaVerified", mfaVerified);
        model.addAttribute("adminOverride", adminOverride);

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

    @GetMapping("/export")
    public void exportCsv(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false, defaultValue = "24") int hours,
            HttpServletResponse response) throws IOException {

        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        DateTimeFormatter ts = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        List<CsvColumn<AuditLog>> columns = List.of(
                new CsvColumn<>("Timestamp", l -> l.getTimestamp() != null ? l.getTimestamp().format(ts) : ""),
                new CsvColumn<>("Category", l -> l.getEventCategory() != null ? l.getEventCategory() : ""),
                new CsvColumn<>("User", l -> l.getPrincipalName() != null ? l.getPrincipalName() : ""),
                new CsvColumn<>("Decision", l -> l.getDecision() != null ? l.getDecision() : ""),
                new CsvColumn<>("Action", l -> l.getAction() != null ? l.getAction() : ""),
                new CsvColumn<>("Resource", l -> l.getRequestUri() != null ? l.getRequestUri() : ""),
                new CsvColumn<>("Risk Score", l -> l.getRiskScore() != null ? String.valueOf(l.getRiskScore()) : ""),
                new CsvColumn<>("IP", l -> l.getClientIp() != null ? l.getClientIp() : ""),
                new CsvColumn<>("HTTP Method", l -> l.getHttpMethod() != null ? l.getHttpMethod() : ""),
                new CsvColumn<>("Reason", l -> l.getReason() != null ? l.getReason() : ""),
                new CsvColumn<>("Source", l -> l.getEventSource() != null ? l.getEventSource() : ""),
                new CsvColumn<>("Session ID", l -> l.getSessionId() != null ? l.getSessionId() : ""),
                new CsvColumn<>("Correlation ID", l -> l.getCorrelationId() != null ? l.getCorrelationId() : "")
        );

        csvExportService.export(response, "audit-log", columns, () -> loadAllLogs(since, category, filter));
    }

    private Stream<AuditLog> loadAllLogs(LocalDateTime since, String category, String filter) {
        int batchSize = 500;
        List<AuditLog> allLogs = new ArrayList<>();
        Pageable pageable = PageRequest.of(0, batchSize, Sort.by(Sort.Direction.DESC, "timestamp"));

        Page<AuditLog> page;
        do {
            if (filter != null && !filter.isBlank()) {
                page = switch (filter) {
                    case "AFTER_HOURS" -> auditLogRepository.findAfterHoursAccess(since, pageable);
                    case "HIGH_RISK" -> auditLogRepository.findByTimestampAfterAndRiskScoreGte(since, 0.4, pageable);
                    case "DECISION_ALLOW" -> auditLogRepository.findByTimestampAfterAndDecision(since, "ALLOW", pageable);
                    case "DECISION_DENY" -> auditLogRepository.findByTimestampAfterAndDecision(since, "DENY", pageable);
                    case "ZT_ALLOW" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "ALLOW", since, pageable);
                    case "ZT_BLOCK" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "BLOCK", since, pageable);
                    case "ZT_CHALLENGE" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "CHALLENGE", since, pageable);
                    case "ZT_ESCALATE" -> auditLogRepository.findByCategoryAndDecision("SECURITY_DECISION", "ESCALATE", since, pageable);
                    default -> auditLogRepository.findByTimestampAfterAndCategory(since, filter, pageable);
                };
            } else if (category != null && !category.isBlank()) {
                page = auditLogRepository.findByTimestampAfterAndCategory(since, category, pageable);
            } else {
                page = auditLogRepository.findByTimestampAfter(since, pageable);
            }
            allLogs.addAll(page.getContent());
            pageable = page.nextPageable();
        } while (page.hasNext());

        return allLogs.stream();
    }
}
