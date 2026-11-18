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

import io.contexa.contexaiam.security.xacml.pep.AuthorizationAuditReason;
import io.contexa.contexaiam.admin.web.monitoring.dto.DecisionRecordIntegrity;
import io.contexa.contexaiam.admin.web.monitoring.service.DecisionRecordSealCheck;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexaiam.admin.web.common.CsvColumn;
import io.contexa.contexaiam.admin.web.common.CsvExportService;
import io.contexa.contexaiam.admin.web.monitoring.dto.SecurityMonitorDtos.IpGroupView;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityEventQueries;
import io.contexa.contexaiam.admin.web.monitoring.service.SecurityEventQueries.Criteria;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.security.access.prepost.PreAuthorize;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import org.springframework.lang.Nullable;
import io.contexa.contexacore.verification.evidence.EvidenceSigner;

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
    /**
     * K93: the periods the screen offers, in hours, and the words of each: up to the dashboard's longest period, so a
     * dashboard link of any period opens with its period chosen.
     */
    static final List<PeriodChoice> PERIODS = List.of(new PeriodChoice(1, "1h"), new PeriodChoice(6, "6h"),
            new PeriodChoice(24, "24h"), new PeriodChoice(72, "3d"), new PeriodChoice(168, "7d"),
            new PeriodChoice(720, "30d"), new PeriodChoice(2160, "90d"));

    /** A period chip: its hours, and the end of the key of its words (admin.security.monitor.period.*). */
    public record PeriodChoice(int hours, String label) {
    }
    /** The rows of a page of the list. */
    static final int PAGE_SIZE = 20;
    /** The rows the CSV reads at a time. */
    static final int CSV_BATCH = 500;

    private final AuditLogRepository auditLogRepository;
    private final CsvExportService csvExportService;
    private final DelegationRegistry delegationRegistry;
    /** docs/agent A5-6: the signer the decision records are verified with; none reads them as not verifiable. */
    private EvidenceSigner evidenceSigner;
    /** docs/agent A5-6: the seal check, with the signer set on this controller. */
    private final DecisionRecordSealCheck sealCheck;
    private MessageSource messageSource;
    /** K138: the list, every filter in one statement; without it the list is empty. */
    private SecurityEventQueries eventQueries;

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
        this.sealCheck = new DecisionRecordSealCheck(auditLogRepository, () -> this.evidenceSigner);
    }

    /** IAM-D05: the notices of the screen in the administrator's language; without it they are in English. */
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    /** docs/agent A5-6: the signer the decision records were signed with. */
    public void setEvidenceSigner(EvidenceSigner evidenceSigner) {
        this.evidenceSigner = evidenceSigner;
    }

    /** K138: the reads of the list, every filter of the screen together. */
    public void setEventQueries(SecurityEventQueries eventQueries) {
        this.eventQueries = eventQueries;
    }

    /** The list without a subject chip, as before A5-5. */
    public String monitor(String category, String filter, String keyword, int hours, int page, Model model) {
        return monitor(category, filter, keyword, null, hours, null, page, model);
    }

    /** The list of the last hours, without a start a link names. */
    public String monitor(String category, String filter, String keyword, String subject, int hours, int page,
                          Model model) {
        return monitor(category, filter, keyword, subject, hours, null, page, model);
    }

    @GetMapping
    public String monitor(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String subject,
            @RequestParam(required = false, defaultValue = "24") int hours,
            @RequestParam(required = false) String from,
            @RequestParam(required = false, defaultValue = "0") int page,
            Model model) {

        model.addAttribute("activePage", "security-monitor");

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime start = start(from, now);
        LocalDateTime since = start != null ? start : now.minusHours(hours);
        // K103: the start a link named stays with the screen's own links (its pages, its categories, its CSV)
        model.addAttribute("from", start != null ? from.trim() : null);
        // docs/agent A5-5: a subject chip lists the decisions of that subject kind.
        String subjectKind = subjectKind(subject);
        model.addAttribute("subject", subjectKind);
        model.addAttribute("subjectKinds", SUBJECT_KINDS);
        Criteria criteria = new Criteria(since, now, category, filter, keyword, subjectKind);
        // K139: a page before the first is the first, a page after the last the last
        Page<AuditLog> logPage = read(criteria, PageRequest.of(Math.max(0, page), PAGE_SIZE));
        if (logPage.getTotalPages() > 0 && logPage.getNumber() >= logPage.getTotalPages()) {
            logPage = read(criteria, PageRequest.of(logPage.getTotalPages() - 1, PAGE_SIZE));
        }
        if (hasText(filter)) {
            model.addAttribute("filterType", filter);
            if (SecurityEventQueries.DISTINCT_IP.equals(filter) && eventQueries != null) {
                // K138: the addresses of the same records, the user name and the subject kind applied
                Page<Object[]> addresses = eventQueries.addresses(criteria, PageRequest.of(logPage.getNumber(), PAGE_SIZE));
                List<IpGroupView> ipGroups = new ArrayList<>();
                for (Object[] row : addresses.getContent()) {
                    ipGroups.add(IpGroupView.fromRow(row));
                }
                model.addAttribute("ipGroups", ipGroups);
                model.addAttribute("totalIpGroups", addresses.getTotalElements());
            }
        }
        model.addAttribute("integrity", integrityOf(logPage.getContent()));

        prepareMonitorModel(model, logPage, hours, category, filter, keyword, since, now);

        return "contexa/admin/security-monitor";
    }

    /** docs/agent A5-5: the subject kind a chip names, none for any other word. */
    @Nullable
    static String subjectKind(@Nullable String subject) {
        return subject != null && SUBJECT_KINDS.contains(subject) ? subject : null;
    }

    private static boolean hasText(@Nullable String value) {
        return value != null && !value.isBlank();
    }

    /**
     * A page of the list as the screen's filters choose it; the screen and its CSV read the same (K108). K138: the
     * user name and the subject kind narrow every list, a category's and a filter's.
     */
    Page<AuditLog> read(Criteria criteria, Pageable pageable) {
        if (eventQueries == null) {
            return new PageImpl<>(List.of(), pageable, 0);
        }
        Page<Long> ids = eventQueries.ids(criteria, pageable);
        if (ids.isEmpty()) {
            return new PageImpl<>(List.of(), pageable, ids.getTotalElements());
        }
        return new PageImpl<>(SecurityEventQueries.inOrder(ids.getContent(),
                auditLogRepository.findAllById(ids.getContent())), pageable, ids.getTotalElements());
    }

    /**
     * K103: the start a link names, an instant (the dashboard's seal count starts at the hour its period starts in);
     * none when it is missing, unreadable or after now, and the screen reads its last hours.
     */
    @Nullable
    static LocalDateTime start(@Nullable String from, LocalDateTime now) {
        if (from == null || from.isBlank()) {
            return null;
        }
        try {
            LocalDateTime start = LocalDateTime.ofInstant(Instant.parse(from.trim()), ZoneId.systemDefault());
            return start.isAfter(now) ? null : start;
        } catch (DateTimeParseException unreadable) {
            log.debug("[SecurityMonitor] The start {} is no instant; the last hours are read", from);
            return null;
        }
    }

    private void prepareMonitorModel(
            Model model, Page<AuditLog> logPage, int hours,
            String category, String filter, String keyword, LocalDateTime since, LocalDateTime until) {
        model.addAttribute("logPage", logPage);
        model.addAttribute("hours", hours);
        model.addAttribute("periods", PERIODS);
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
        // K102: the overrides of the screen's period as the dashboard counts them, a refused one none
        model.addAttribute("adminOverride", auditLogRepository.countAdminOverridesBetween(since, until));
    }

    @GetMapping("/{id:\\d+}")
    public String detail(@PathVariable Long id, Model model, RedirectAttributes ra) {
        model.addAttribute("activePage", "security-monitor");

        AuditLog auditLog = auditLogRepository.findById(id).orElse(null);
        if (auditLog == null) {
            // The list says why it is shown instead (IAM-D05); the ID as typed, not as a number with separators (IAM-D06).
            String fallback = "No security event has the ID " + id + ". It may have been removed when its retention ended.";
            String message = messageSource == null ? fallback : messageSource.getMessage(
                    "admin.security.monitor.not.found", new Object[]{String.valueOf(id)}, fallback,
                    LocaleContextHolder.getLocale());
            ra.addFlashAttribute("errorMessage", message);
            log.warn("[SecurityMonitor] No audit log has the ID {}", id);
            return "redirect:/contexa/admin/security-monitor";
        }

        model.addAttribute("log", auditLog);
        // D29: an authorization reason is a code, shown in the language of the screen; any other reason as stored.
        model.addAttribute("reason", AuthorizationAuditReason.describe(auditLog.getReason()));
        // docs/agent A5-5: an agent's decision shows the delegation it ran under, as the delegation record states it.
        model.addAttribute("delegation", delegationOf(auditLog));
        // docs/agent A5-6: whether the decision record is as it was sealed.
        model.addAttribute("integrity", integrityOf(List.of(auditLog)).of(auditLog.getId()));
        return "contexa/admin/security-monitor-detail";
    }

    /**
     * docs/agent A5-6: the integrity of each decision record on the page (VERIFIED, MISMATCH or UNVERIFIABLE), by
     * record ID; records that are no decisions have none.
     */
    private DecisionRecordIntegrity integrityOf(List<AuditLog> records) {
        DecisionRecordIntegrity integrity = new DecisionRecordIntegrity();
        for (AuditLog record : records) {
            if (DecisionRecordSealCheck.sealed(record)) {
                // The oldest kept record names a previous record the audit retention deleted: not a mismatch.
                integrity.found(record.getId(), sealCheck.check(record).name());
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

    /** The CSV of the last hours, without a start a link names, a user name or a subject chip. */
    public void exportCsv(String category, String filter, int hours, HttpServletResponse response) throws IOException {
        exportCsv(category, filter, hours, null, null, null, response);
    }

    /** K108: the CSV holds the rows the screen lists, with every filter the screen was opened with. */
    @GetMapping("/export")
    public void exportCsv(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String filter,
            @RequestParam(required = false, defaultValue = "24") int hours,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) String subject,
            HttpServletResponse response) throws IOException {

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime start = start(from, now);
        LocalDateTime since = start != null ? start : now.minusHours(hours);
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

        String subjectKind = subjectKind(subject);
        csvExportService.export(response, "audit-log", columns,
                () -> loadAllLogs(category, filter, keyword, subjectKind, since, now));
    }

    /** Every row of the list, read as the screen reads its pages. */
    private Stream<AuditLog> loadAllLogs(@Nullable String category, @Nullable String filter, @Nullable String keyword,
                                         @Nullable String subjectKind, LocalDateTime since, LocalDateTime until) {
        List<AuditLog> allLogs = new ArrayList<>();
        Criteria criteria = new Criteria(since, until, category, filter, keyword, subjectKind);
        Pageable pageable = PageRequest.of(0, CSV_BATCH);
        Page<AuditLog> page;
        do {
            page = read(criteria, pageable);
            allLogs.addAll(page.getContent());
            pageable = pageable.next();
        } while (page.hasNext());
        return allLogs.stream();
    }
}
