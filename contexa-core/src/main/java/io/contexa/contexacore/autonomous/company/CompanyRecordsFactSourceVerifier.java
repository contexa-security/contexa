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
package io.contexa.contexacore.autonomous.company;

import io.contexa.contexacore.autonomous.agent.AgentDelegation;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Approval;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.OnCall;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet.Usage;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AssignmentRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier;
import io.contexa.contexacore.verification.inspection.PromptInspectionSubject;
import io.contexa.contexacore.verification.inspection.PromptInspectionUnavailableException;
import org.springframework.dao.DataAccessException;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The source truth check's reading of Contexa's own records (docs/agent OC-4): for a sealed decision, the company
 * records (OC-2) and the delegation (OC-1) it was judged with are read again from their stores, by queries of their
 * own and at the request's time, and given as the pieces the prompt's lines must hold:
 * <ul>
 *     <li>whether the person was on call, and whether they were assigned to the target (or its account manager), when
 *     the decision looked these up;</li>
 *     <li>the approval the prompt's approval line names: its approver, its item limit and what was delivered under it
 *     before the request;</li>
 *     <li>the delegation record the decision used: its agent and person, its objective, and who wrote it.</li>
 * </ul>
 * A person or delegation the decision used and the stores no longer hold (the account was deleted) is reported as
 * records not kept; a store that cannot be read now has the package inspected again later. An application with its
 * own sources declares its own {@link PromptFactSourceVerifier}.
 */
public class CompanyRecordsFactSourceVerifier implements PromptFactSourceVerifier {

    static final String RECORDS = "contexa company records ";
    static final String DELEGATIONS = "contexa delegation registry";
    private static final Pattern APPROVAL = Pattern.compile("^(\\S+) by ");

    private final CompanyRecordStore records;
    @Nullable
    private final DelegationRegistry delegations;

    public CompanyRecordsFactSourceVerifier(CompanyRecordStore records, @Nullable DelegationRegistry delegations) {
        if (records == null) {
            throw new IllegalArgumentException("A company record store is required");
        }
        this.records = records;
        this.delegations = delegations;
    }

    @Override
    public List<SourceFact> sourceFacts(PromptInspectionSubject subject) {
        return read(subject).facts();
    }

    @Override
    public SourceReading read(PromptInspectionSubject subject) {
        CanonicalSecurityContext context = subject.canonicalContext();
        if (context == null || context.getRequestObservedAt() == null) {
            return SourceReading.kept(List.of());
        }
        try {
            List<SourceFact> facts = new ArrayList<>();
            FrictionProfile friction = context.getFrictionProfile();
            if (usedRecords(friction)) {
                String holder = text(friction.getRecordsHolderId());
                if (holder == null && context.getActor() != null) {
                    holder = text(context.getActor().getUserId());
                }
                CompanyRecordSet person = holder == null ? CompanyRecordSet.EMPTY : person(context, holder);
                if (person.people().isEmpty()) {
                    return SourceReading.notKept(RECORDS + "(person)");
                }
                companyFacts(facts, friction, person, context, subject.prompt());
            }
            String delegationId = context.getAttributes() != null
                    ? text(context.getAttributes().get(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE)) : null;
            if (delegations != null && delegationId != null) {
                Optional<AgentDelegation> delegation = delegations.find(delegationId);
                if (delegation.isEmpty()) {
                    return SourceReading.notKept(DELEGATIONS);
                }
                delegationFacts(facts, delegation.get(), context);
            }
            return SourceReading.kept(facts);
        } catch (DataAccessException e) {
            throw new PromptInspectionUnavailableException("Contexa's company records cannot be read now", e);
        }
    }

    private CompanyRecordSet person(CanonicalSecurityContext context, String holder) {
        String tenant = context.getActor() != null ? text(context.getActor().getTenantId()) : null;
        CompanyRecordSet person = records.ofSubject(tenant, holder);
        return tenant != null ? person.plus(records.ofSubject(null, holder)) : person;
    }

    private static void companyFacts(List<SourceFact> facts, FrictionProfile friction, CompanyRecordSet person,
                                     CanonicalSecurityContext context, InspectedPrompt prompt) {
        Instant at = context.getRequestObservedAt();
        if (friction.getOnCall() != null) {
            boolean onCall = person.onCall().stream().anyMatch(shift -> active(shift, at));
            facts.add(onCall
                    ? fact("OnCall", "on call", "not on call", "on call")
                    : fact("OnCall", "not on call", null, "on call"));
        }
        AssignmentRecord assignment = friction.getAssignment();
        String target = assignment != null ? text(assignment.getTarget()) : null;
        if (target != null) {
            LocalDate day = LocalDate.ofInstant(at, ZoneOffset.UTC);
            boolean manager = CompanyRecordSet.ACCOUNT_MANAGER.equalsIgnoreCase(
                    String.valueOf(assignment.getResponsibility()));
            boolean held = person.assignments().stream().anyMatch(record -> target.equals(record.target())
                    && record.accountManager() == manager && record.validOn(day));
            String holds = (manager ? "account manager of " : "assigned to ") + target;
            String lacks = (manager ? "not the account manager of " : "not assigned to ") + target;
            facts.add(held ? fact("Assignment", holds, lacks, "assignment") : fact("Assignment", lacks, null,
                    "assignment"));
        }
        approvalKey(prompt).flatMap(key -> person.approvals().stream().filter(record -> key.equals(record.id()))
                .findFirst()).ifPresent(approval -> facts.addAll(approvalFacts(approval, person, context)));
    }

    /**
     * The approval's approver and limit, and what was delivered under it before the request when the application reports
     * it and the request stays within the limit (the prompt states the use only then).
     */
    private static List<SourceFact> approvalFacts(Approval approval, CompanyRecordSet person,
                                                  CanonicalSecurityContext context) {
        List<SourceFact> facts = new ArrayList<>();
        if (approval.approver() != null) {
            facts.add(fact("Approval", approval.id() + " by " + approval.approver(), null, "approval"));
        }
        Integer limit = approval.maxItems() != null && approval.maxItems() > 0 ? approval.maxItems() : null;
        if (limit != null) {
            facts.add(fact("Approval", "up to " + number(limit) + " items", null, "approval"));
        }
        Integer items = context.getResource() != null ? context.getResource().getRequestedItems() : null;
        if (limit != null && items != null && items <= limit && Boolean.TRUE.equals(approval.usageReported())) {
            Instant at = context.getRequestObservedAt();
            Instant until = approval.validUntil() != null && approval.validUntil().isBefore(at)
                    ? approval.validUntil() : at;
            int used = person.usage().stream()
                    .filter(record -> Objects.equals(approval.target(), record.target()) && record.at() != null
                            && (approval.validFrom() == null || !record.at().isBefore(approval.validFrom()))
                            && record.at().isBefore(until))
                    .mapToInt(Usage::items).sum();
            facts.add(fact("Approval", "used " + number(used) + " before this request", null, "usage"));
        }
        return facts;
    }

    private static void delegationFacts(List<SourceFact> facts, AgentDelegation delegation,
                                        CanonicalSecurityContext context) {
        if (context.getDelegation() != null && context.getDelegation().hasMandate()) {
            facts.add(new SourceFact(PromptBlock.DECISION_FACTS, "Delegation", "agent " + delegation.agentId() + " for "
                    + delegation.delegatorId(), null, DELEGATIONS));
            String objective = text(delegation.objectiveFamily()) != null ? delegation.objectiveFamily()
                    : text(delegation.objectiveId());
            if (objective != null) {
                facts.add(new SourceFact(PromptBlock.DECISION_FACTS, "Delegation", "objective " + objective, null,
                        DELEGATIONS));
            }
        }
        if (text(delegation.recordedBy()) != null) {
            facts.add(new SourceFact(PromptBlock.DECISION_FACTS, "RecordProvenance", "delegation "
                    + delegation.delegationId() + " recorded by " + delegation.recordedBy().trim(), null, DELEGATIONS));
        }
    }

    /** Whether the decision was judged with company records: a rule, a record, or a kind it looked up. */
    private static boolean usedRecords(@Nullable FrictionProfile friction) {
        return friction != null && ((friction.getPolicies() != null && !friction.getPolicies().isEmpty())
                || (friction.getCheckedRecordKinds() != null && !friction.getCheckedRecordKinds().isEmpty())
                || friction.getAssignment() != null || friction.getOnCall() != null
                || (friction.getApprovalRecords() != null && !friction.getApprovalRecords().isEmpty())
                || (friction.getTicketRecords() != null && !friction.getTicketRecords().isEmpty()));
    }

    private static boolean active(OnCall shift, Instant at) {
        return (shift.startsAt() == null || !at.isBefore(shift.startsAt()))
                && (shift.endsAt() == null || at.isBefore(shift.endsAt()));
    }

    /** The approval the prompt names on its approval line, which the store then reads by its key. */
    private static Optional<String> approvalKey(@Nullable InspectedPrompt prompt) {
        if (prompt == null) {
            return Optional.empty();
        }
        return prompt.lines().stream()
                .filter(line -> line.kind() == InspectedPrompt.Kind.ENTRY && line.entryLine() != null)
                .filter(line -> line.block() == PromptBlock.DECISION_FACTS && "Approval".equals(line.entryLine().label()))
                .map(line -> APPROVAL.matcher(line.entryLine().value()))
                .filter(Matcher::find).map(matcher -> matcher.group(1)).findFirst();
    }

    private static SourceFact fact(String entry, String fragment, @Nullable String excluded, String kind) {
        return new SourceFact(PromptBlock.DECISION_FACTS, entry, fragment, excluded, RECORDS + kind);
    }

    private static String number(int value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
