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
package io.contexa.contexaiam.admin.web.monitoring.controller;

import java.util.Locale;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.common.CsvColumn;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.monitoring.dto.SecurityMonitorDtos.IpGroupView;
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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.security.access.prepost.PreAuthorize;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import org.springframework.lang.Nullable;
import io.contexa.contexacore.autonomous.audit.DecisionRecordSeal;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;
import java.util.HashMap;
import java.util.Map;

/**
 * Security Monitor - real-time security event viewer based on ctxa_audit_log.
 * All queries use DB-level pagination to handle millions of records.
 */
@Controller
@RequestMapping("/contexa/admin/security-monitor")
@Slf4j
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class SecurityMonitorController {

    /** docs/agent A5-5: the subject chips the list filters by (A1-3 subject kinds). */
    static final List<String> SUBJECT_KINDS = List.of("HUMAN_USER", "DELEGATED_AGENT", "AUTONOMOUS_AGENT");

    private final AuditLogRepository auditLogRepository;
    private final CsvExportService csvExportService;
    private final DelegationRegistry delegationRegistry;
    /** docs/agent A5-6: the signer the decision records are verified with; none reads them as not verifiable. */
    private EvidenceSigner evidenceSigner;

    public SecurityMonitorController(AuditLogRepository auditLogRepository, CsvExportService csvExportService) {
        this(auditLogRepository, csvExportService, null);
    }

    /**
     * @param delegationRegistry the delegations Contexa keeps (OC-1), for the delegation a decision ran under; null
     *                           without one, and the record's own fields are shown
     */
    public SecurityMonitorController(AuditLogRepository auditLogRepository, CsvExportService csvExportService,
                                     @Nullable DelegationRegistry delegationRegistry) {
        this.auditLogRepository = auditLogRepository;
        this.csvExportService = csvExportService;
        this.delegationRegistry = delegationRegistry;
    }

    /** docs/agent A5-6: the signer the decision records were signed with. */
    public void setEvidenceSigner(EvidenceSigner evidenceSigner) {
        this.evidenceSigner = evidenceSigner;
    }

    /** The list without a subject chip, as before A5-5. */
    public String monitor(String category, String filter, String keyword, int hours, int page, Model model) {
        return monitor(category, filter, keyword, null, hours, page, model);
    }

    @GetMapping
    public String monitor(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String subject,
            @RequestParam(required = false, defaultValue = "24") int hours,
            @RequestParam(required = false, defaultValue = "0") int page,
            Model model) {

        model.addAttribute("activePage", "security-monitor");

        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        // docs/agent A5-5: a subject chip lists the decisions of that subject kind.
        String subjectKind = subject != null && SUBJECT_KINDS.contains(subject) ? subject : null;
        model.addAttribute("subject", subjectKind);
        model.addAttribute("subjectKinds", SUBJECT_KINDS);
        Page<AuditLog> logPage = subjectKind != null
                ? auditLogRepository.findByTimestampAfterAndSubjectKind(since, subjectKind,
                PageRequest.of(page, 20, Sort.by(Sort.Direction.DESC, "timestamp")))
                : loadLogPage(category, filter, keyword, page, since, model);
        model.addAttribute("integrity", integrityOf(logPage.getContent()));

        prepareMonitorModel(model, logPage, hours, category, filter, keyword, since);

        return "contexa/admin/security-monitor";
    }

    private Page<AuditLog> loadLogPage(
            String category, String filter, String keyword, int page,
            LocalDateTime since, Model model) {
        int pageSize = 20;
        Pageable pageable = PageRequest.of(page, pageSize, Sort.by(Sort.Direction.DESC, "timestamp"));
        boolean hasKeyword = keyword != null && !keyword.isBlank();
        String likePattern = hasKeyword ? "%" + keyword.trim().toLowerCase(Locale.ROOT) + "%" : null;
        if (filter != null && !filter.isBlank()) {
            model.addAttribute("filterType", filter);
            Page<AuditLog> logPage = switch (filter) {
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
            if ("DISTINCT_IP".equals(filter)) {
                List<Object[]> rows = auditLogRepository.findIpGroupsSince(since, pageSize, page * pageSize);
                List<IpGroupView> ipGroups = new ArrayList<>();
                for (Object[] row : rows) {
                    ipGroups.add(IpGroupView.fromRow(row));
                }
                model.addAttribute("ipGroups", ipGroups);
                model.addAttribute("totalIpGroups", auditLogRepository.countDistinctIpGroupsSince(since));
            }
            return logPage;
        }
        if (hasKeyword && category != null && !category.isBlank()) {
            return auditLogRepository.findByTimestampAfterAndCategoryAndPrincipalNameLike(
                    since, category, likePattern, pageable);
        }
        if (hasKeyword) {
            return auditLogRepository.findByTimestampAfterAndPrincipalNameLike(since, likePattern, pageable);
        }
        if (category != null && !category.isBlank()) {
            return auditLogRepository.findByTimestampAfterAndCategory(since, category, pageable);
        }
        return auditLogRepository.findByTimestampAfter(since, pageable);
    }

    private void prepareMonitorModel(
            Model model, Page<AuditLog> logPage, int hours,
            String category, String filter, String keyword, LocalDateTime since) {
        model.addAttribute("logPage", logPage);
        model.addAttribute("hours", hours);
        model.addAttribute("category", category);
        model.addAttribute("filter", filter);
        model.addAttribute("keyword", keyword);
        model.addAttribute("totalCount", auditLogRepository.countByTimestampAfter(since));
        model.addAttribute("authSuccess", auditLogRepository.countByEventCategoryAndTimestampAfter(
                "AUTHENTICATION_SUCCESS", since));
        model.addAttribute("authFailure", auditLogRepository.countByEventCategoryAndTimestampAfter(
                "AUTHENTICATION_FAILURE", since));
        model.addAttribute("securityDecision", auditLogRepository.countZeroTrustTotalSince(since));
        model.addAttribute("userBlocked", auditLogRepository.countByEventCategoryAndTimestampAfter(
                "USER_BLOCKED", since));
        model.addAttribute("mfaVerified", auditLogRepository.countByEventCategoryAndTimestampAfter(
                "MFA_VERIFICATION_SUCCESS", since));
        model.addAttribute("adminOverride", auditLogRepository.countAdminOverridesSince(since));
    }

    @GetMapping("/{id:\\d+}")
    public String detail(@PathVariable Long id, Model model, RedirectAttributes ra) {
        model.addAttribute("activePage", "security-monitor");

        AuditLog auditLog = auditLogRepository.findById(id).orElse(null);
        if (auditLog == null) {
            String message = "Audit log not found: " + id;
            ra.addFlashAttribute("errorMessage", message);
            log.warn(message);
            return "redirect:/contexa/admin/security-monitor";
        }

        model.addAttribute("log", auditLog);
        // docs/agent A5-5: an agent's decision shows the delegation it ran under, as the delegation record states it.
        model.addAttribute("delegation", delegationOf(auditLog));
        // docs/agent A5-6: whether the decision record is as it was sealed.
        model.addAttribute("integrity", integrityOf(List.of(auditLog)).get(auditLog.getId()));
        return "contexa/admin/security-monitor-detail";
    }

    /**
     * docs/agent A5-6: the integrity of each decision record on the page (VERIFIED, MISMATCH or UNVERIFIABLE), by
     * record ID; records that are no decisions have none.
     */
    private Map<Long, String> integrityOf(List<AuditLog> records) {
        Map<Long, String> integrity = new HashMap<>();
        for (AuditLog record : records) {
            if (record.getId() == null || !"SECURITY_DECISION".equals(record.getEventCategory())) {
                continue;
            }
            try {
                // The oldest kept record names a previous record the audit retention deleted: not a mismatch.
                integrity.put(record.getId(), DecisionRecordSeal.evaluate(record, evidenceSigner,
                        auditLogRepository::existsByRecordHash, kept -> auditLogRepository
                                .existsByEventCategoryAndRecordHashIsNotNullAndIdLessThan("SECURITY_DECISION",
                                        kept.getId())).name());
            } catch (RuntimeException e) {
                log.error("Integrity check failed for audit log {}", record.getId(), e);
                integrity.put(record.getId(), "UNVERIFIABLE");
            }
        }
        return integrity;
    }

    @Nullable
    private AgentDelegation delegationOf(AuditLog auditLog) {
        if (delegationRegistry == null || auditLog.getDelegationId() == null || auditLog.getDelegationId().isBlank()) {
            return null;
        }
        try {
            return delegationRegistry.find(auditLog.getDelegationId()).orElse(null);
        } catch (RuntimeException e) {
            log.error("Delegation lookup failed for audit log {}: delegationId={}", auditLog.getId(),
                    auditLog.getDelegationId(), e);
            return null;
        }
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
