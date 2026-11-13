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
package io.contexa.contexaiam.admin.web.company.controller;

import io.contexa.contexacore.autonomous.company.CompanyRecordKind;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.AccessDay;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Approval;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Assignment;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.NetworkZone;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.OnCall;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Person;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Policy;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Ticket;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Travel;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Usage;
import io.contexa.contexacore.autonomous.company.CompanyRecordStore.StoredCompanyRecord;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService.InvalidRecordsException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The console's company records (docs/agent OC-2): what the company's integrations put, by kind, person and target,
 * with who put each and when. It shows the records as they are kept and decides nothing.
 */
@Controller
@RequestMapping("/contexa/admin/company-records")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class CompanyRecordsAdminController {

    static final int PAGE = 200;

    private final CompanyRecordsAdminService records;

    public CompanyRecordsAdminController(CompanyRecordsAdminService records) {
        this.records = records;
    }

    @GetMapping
    public String list(@RequestParam(value = "kind", required = false) String kind,
                       @RequestParam(value = "subject", required = false) String subject,
                       @RequestParam(value = "target", required = false) String target,
                       @RequestParam(value = "tenantId", required = false) String tenantId, Model model) {
        List<RecordRow> rows = List.of();
        try {
            rows = records.list(blank(tenantId), blank(kind), blank(subject), blank(target), PAGE).stream()
                    .map(CompanyRecordsAdminController::row).toList();
        } catch (InvalidRecordsException e) {
            model.addAttribute("errorMessage", e.getMessage());
        }
        model.addAttribute("records", rows);
        model.addAttribute("kinds", Arrays.stream(CompanyRecordKind.values()).map(Enum::name).toList());
        model.addAttribute("currentKind", blank(kind));
        // Empty rather than absent, so the console's links carry each filter as an empty value.
        model.addAttribute("subject", Objects.requireNonNullElse(blank(subject), ""));
        model.addAttribute("target", Objects.requireNonNullElse(blank(target), ""));
        model.addAttribute("tenantId", Objects.requireNonNullElse(blank(tenantId), ""));
        model.addAttribute("pageLimit", PAGE);
        return "contexa/admin/company-records";
    }

    static RecordRow row(StoredCompanyRecord stored) {
        return new RecordRow(stored.kind().name(), stored.key(), stored.subject(), stored.target(),
                summary(stored.record()), stored.ingestedBy(), stored.ingestedAt());
    }

    /** The record's values in one line, those it states only. */
    static String summary(Object record) {
        if (record instanceof Person person) {
            return join("company id " + text(person.companyId()), person.displayName());
        }
        if (record instanceof Assignment assignment) {
            return join(assignment.responsibility(), period(assignment.from(), assignment.until()));
        }
        if (record instanceof Approval approval) {
            return join(approval.status(), approval.purpose(), "approver " + text(approval.approver()),
                    approval.maxItems() != null ? "up to " + approval.maxItems() + " items" : null,
                    actions(approval.actions()), period(approval.validFrom(), approval.validUntil()),
                    approval.decidedAt() != null ? "decided " + approval.decidedAt() : null,
                    Boolean.TRUE.equals(approval.usageReported()) ? "usage reported" : null,
                    approval.recordedBy() != null ? "recorded by " + approval.recordedBy() : null);
        }
        if (record instanceof Ticket ticket) {
            return join(ticket.kind(), ticket.status(), ticket.purpose(), "approver " + text(ticket.approver()),
                    actions(ticket.actions()), period(ticket.validFrom(), ticket.validUntil()),
                    ticket.recordedBy() != null ? "recorded by " + ticket.recordedBy() : null);
        }
        if (record instanceof OnCall shift) {
            return join(shift.team(), period(shift.startsAt(), shift.endsAt()));
        }
        if (record instanceof Travel trip) {
            return join(join(trip.city(), trip.country()), trip.network(), period(trip.validFrom(), trip.validUntil()));
        }
        if (record instanceof AccessDay day) {
            return String.valueOf(day.day());
        }
        if (record instanceof Usage used) {
            return join(used.items() + " items", String.valueOf(used.at()));
        }
        if (record instanceof Policy policy) {
            return join(policy.requirement(), policy.requiredTicketKind(), actions(policy.actions()),
                    policy.categories().isEmpty() ? null : "categories " + String.join(", ", policy.categories()),
                    policy.exceptions().isEmpty() ? null : "exceptions " + policy.exceptions().stream()
                            .map(rule -> rule.kind() + (rule.limit() != null ? " " + rule.limit() : ""))
                            .collect(Collectors.joining(", ")),
                    policy.statement());
        }
        if (record instanceof NetworkZone network) {
            return network.zone();
        }
        return String.valueOf(record);
    }

    private static String actions(List<String> actions) {
        return actions.isEmpty() ? null : "actions " + String.join(", ", actions);
    }

    private static String period(Object from, Object until) {
        if (from == null && until == null) {
            return null;
        }
        return (from != null ? from : "") + " .. " + (until != null ? until : "");
    }

    private static String join(String... parts) {
        List<String> stated = new ArrayList<>();
        for (String part : parts) {
            if (part != null && !part.isBlank()) {
                stated.add(part);
            }
        }
        return String.join(" · ", stated);
    }

    private static String text(String value) {
        return Objects.requireNonNullElse(value, "-");
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
