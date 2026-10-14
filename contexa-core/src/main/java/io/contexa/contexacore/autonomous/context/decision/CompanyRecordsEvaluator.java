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
package io.contexa.contexacore.autonomous.context.decision;

import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AccessHistoryRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AssignmentRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.CompanyPolicy;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.OnCallRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PolicyException;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.TicketRecord;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The company records of a request checked at the time of the request (W2-5). The host states its records and its own
 * verdict on them (the conditions it found failing); the engine computes what holds when the request was made: whether
 * the decision was recorded before the request, whether the request falls in the record's validity, whether it stays
 * within the record's limit alone and together with what the session already exported under it, and whether the
 * company's policy is satisfied by a record or by one of its exceptions. Which target a record covers is the host's
 * key, so the engine takes the host's TARGET verdict rather than comparing keys it does not know.
 */
public final class CompanyRecordsEvaluator {

    /** Approval states that cover a request. */
    static final Set<String> APPROVED_STATES = Set.of("APPROVED", "GRANTED", "COMPLETED");

    /** Ticket states in which a ticket no longer, or not yet, covers anything. */
    static final Set<String> INACTIVE_TICKET_STATES = Set.of(
            "CLOSED", "RESOLVED", "CANCELLED", "CANCELED", "REJECTED", "EXPIRED", "DRAFT", "PENDING");

    /** The responsibility of an assignment that makes the requester the account manager of a customer. */
    static final String ACCOUNT_MANAGER = "ACCOUNT_MANAGER";

    private static final String ALLOW = "ALLOW";
    private static final DateTimeFormatter WALL_CLOCK = DateTimeFormatter.ofPattern("MM-dd HH:mm", Locale.ROOT);

    private CompanyRecordsEvaluator() {
    }

    /**
     * The request the records are checked against.
     *
     * @param at               when the request was observed (event clock), null when unknown
     * @param target           the URL template's variables bound to the path ({@code projectKey=GB-500}), null without
     * @param items            how many items the request asks for, null when the host did not say
     * @param sessionDecisions the session's earlier decisions, oldest first
     */
    public record Request(Instant at, String target, Integer items, List<SessionDecisionRecord> sessionDecisions) {

        public Request {
            sessionDecisions = sessionDecisions == null ? List.of() : List.copyOf(sessionDecisions);
        }

        /** The request of a canonical context, with the session's decisions given apart. */
        public static Request of(CanonicalSecurityContext context, List<SessionDecisionRecord> sessionDecisions) {
            if (context == null) {
                return new Request(null, null, null, sessionDecisions);
            }
            CanonicalSecurityContext.Resource resource = context.getResource();
            String target = resource != null
                    ? BaselineViewCalculator.target(resource.getPathFamily(), resource.getRequestPath())
                    : null;
            return new Request(context.getRequestObservedAt(), target,
                    resource != null ? resource.getRequestedItems() : null, sessionDecisions);
        }

        /** The values of the target's variables: {@code GB-500} for {@code projectKey=GB-500}. */
        public String targetValues() {
            if (target == null) {
                return null;
            }
            return Arrays.stream(target.split(","))
                    .map(binding -> binding.contains("=") ? binding.substring(binding.indexOf('=') + 1) : binding)
                    .collect(Collectors.joining(","));
        }
    }

    /**
     * The checked records and the policy satisfaction.
     *
     * @param approvals the approval records, each checked
     * @param tickets   the ticket records, each checked
     * @param onCall    whether the requester is on call at the request time, null when the host did not say
     * @param policy    whether the company's policies are satisfied
     * @param policiesStated whether the host stated the company's policies for the request
     */
    public record Evaluation(List<RecordCheck> approvals, List<RecordCheck> tickets, Boolean onCall,
                             PolicySatisfaction policy, boolean policiesStated) {

        public static final Evaluation NONE = new Evaluation(List.of(), List.of(), null, PolicySatisfaction.UNKNOWN,
                false);

        public Evaluation {
            approvals = approvals == null ? List.of() : List.copyOf(approvals);
            tickets = tickets == null ? List.of() : List.copyOf(tickets);
            policy = policy == null ? PolicySatisfaction.UNKNOWN : policy;
        }

        /** An evaluation whose policies count as stated when it weighed any. */
        public Evaluation(List<RecordCheck> approvals, List<RecordCheck> tickets, Boolean onCall,
                          PolicySatisfaction policy) {
            this(approvals, tickets, onCall, policy, policy != null && !policy.policyIds().isEmpty());
        }

        /**
         * The record that covers the work at the request time. Where the host states its policies, only a record
         * that satisfies them covers the work: a valid ticket where an approval is required covers nothing
         * (P2 correction 3). Without stated policies, the first valid approval, else the first valid ticket.
         */
        public Optional<RecordCheck> covering() {
            if (policiesStated) {
                if (!Boolean.TRUE.equals(policy.satisfied())) {
                    return Optional.empty();
                }
                return approvals.stream()
                        .filter(check -> check.valid() && policy.recordIds().contains(check.recordId()))
                        .findFirst()
                        .or(() -> tickets.stream()
                                .filter(check -> check.valid() && policy.recordIds().contains(check.recordId()))
                                .findFirst());
            }
            return approvals.stream().filter(RecordCheck::valid).findFirst()
                    .or(() -> tickets.stream().filter(RecordCheck::valid).findFirst());
        }
    }

    /** Whether the host looked up records of the kind for the request (P2 correction 3). */
    public static boolean checked(FrictionProfile profile, String kind) {
        return profile != null && profile.getCheckedRecordKinds() != null
                && profile.getCheckedRecordKinds().stream().anyMatch(kind::equalsIgnoreCase);
    }

    /** Whether the profile holds records whose validity the engine computes: approvals or tickets. */
    public static boolean hasRecords(FrictionProfile profile) {
        return profile != null
                && ((profile.getApprovalRecords() != null && !profile.getApprovalRecords().isEmpty())
                || (profile.getTicketRecords() != null && !profile.getTicketRecords().isEmpty()));
    }

    public static Evaluation evaluate(FrictionProfile profile, Request request, ZoneId zone) {
        if (profile == null || request == null) {
            return Evaluation.NONE;
        }
        ZoneId clock = zone != null ? zone : ZoneId.systemDefault();
        List<RecordCheck> approvals = new ArrayList<>();
        if (profile.getApprovalRecords() != null) {
            for (ApprovalRecord record : profile.getApprovalRecords()) {
                if (record != null && StringUtils.hasText(record.getApprovalId())) {
                    approvals.add(checkApproval(record, request, clock));
                }
            }
        }
        List<RecordCheck> tickets = new ArrayList<>();
        if (profile.getTicketRecords() != null) {
            for (TicketRecord record : profile.getTicketRecords()) {
                if (record != null && StringUtils.hasText(record.getTicketId())) {
                    tickets.add(checkTicket(record, request, clock));
                }
            }
        }
        Boolean onCall = onCallAt(profile.getOnCall(), request.at());
        PolicySatisfaction policy = satisfaction(profile, request, approvals, tickets, onCall);
        boolean policiesStated = profile.getPolicies() != null
                && profile.getPolicies().stream().anyMatch(stated -> stated != null);
        return new Evaluation(approvals, tickets, onCall, policy, policiesStated);
    }

    static RecordCheck checkApproval(ApprovalRecord record, Request request, ZoneId zone) {
        Failures failures = new Failures();
        Set<String> host = upper(record.getHostMismatches());
        String status = upper(record.getStatus());
        if (status != null && !APPROVED_STATES.contains(status)) {
            failures.add(PolicyReason.NO_RECORD, "is " + status);
        }
        else if (status == null && host.contains("STATUS")) {
            failures.add(PolicyReason.NO_RECORD, "is not in an approved state (host)");
        }
        if (host.contains("APPROVER")) {
            failures.add(PolicyReason.NO_RECORD, "was approved by the requester (host)");
        }
        if (host.contains("PURPOSE")) {
            failures.add(PolicyReason.NO_RECORD, "has a purpose that does not cover this action (host)");
        }
        if (host.contains("TARGET")) {
            failures.add(PolicyReason.OTHER_TARGET, "covers another target (host)");
        }
        checkValidity(failures, record.getValidFrom(), record.getValidUntil(), host, request.at(), zone);
        if (record.getDecidedAt() != null && request.at() != null && record.getDecidedAt().isAfter(request.at())) {
            failures.add(PolicyReason.LATE, "decided " + RelativeTime.of(record.getDecidedAt(), request.at()));
        }
        Integer usedBefore = null;
        Integer limit = record.getMaxItems();
        Integer items = request.items();
        if (limit != null && items != null) {
            if (items > limit || host.contains("ITEMS")) {
                failures.add(PolicyReason.OVER_LIMIT, number(items) + " items over the limit of " + number(limit));
            }
            else if (record.getUsedItems() != null) {
                usedBefore = record.getUsedItems();
                if (usedBefore + items > limit) {
                    failures.add(PolicyReason.CUMULATIVE, "cumulative " + number(usedBefore + items) + " of "
                            + number(limit) + " items with " + number(usedBefore) + " already exported under it");
                }
            }
            else {
                // Without the host's count of what was exported under the record only this session is known: over
                // the limit there is a failure, within it the rest of the record's use is not known.
                usedBefore = usedInSession(request, record.getValidFrom(), record.getValidUntil());
                if (usedBefore != null && usedBefore + items > limit) {
                    failures.add(PolicyReason.CUMULATIVE, "cumulative " + number(usedBefore + items) + " of "
                            + number(limit) + " items with " + number(usedBefore)
                            + " already exported in this session");
                }
                else {
                    failures.unknown("the items exported under it outside this session (the host does not report "
                            + "them)");
                }
            }
        }
        else if (host.contains("ITEMS")) {
            failures.add(PolicyReason.OVER_LIMIT, "asks for more items than it allows (host)");
        }
        else if (limit != null) {
            failures.unknown("the request's item count against its limit of " + number(limit)
                    + " (the request does not state it)");
        }
        return failures.check(record.getApprovalId(), RecordCheck.APPROVAL, usedBefore, false);
    }

    static RecordCheck checkTicket(TicketRecord record, Request request, ZoneId zone) {
        Failures failures = new Failures();
        boolean claimFalse = Boolean.TRUE.equals(record.getClaimedByRequester())
                && Boolean.FALSE.equals(record.getExists());
        if (claimFalse) {
            failures.add(PolicyReason.NO_RECORD, "named by the requester does not exist");
            return failures.check(record.getTicketId(), RecordCheck.TICKET, null, true);
        }
        Set<String> host = upper(record.getHostMismatches());
        String status = upper(record.getStatus());
        if (status != null && INACTIVE_TICKET_STATES.contains(status)) {
            failures.add(PolicyReason.NO_RECORD, "is " + status);
        }
        else if (host.contains("STATUS")) {
            failures.add(PolicyReason.NO_RECORD, "is not in an active state (host)");
        }
        if (host.contains("APPROVER")) {
            failures.add(PolicyReason.NO_RECORD, "was approved by the requester (host)");
        }
        if (host.contains("PURPOSE")) {
            failures.add(PolicyReason.NO_RECORD, "has a purpose that does not cover this action (host)");
        }
        if (host.contains("TARGET")) {
            failures.add(PolicyReason.OTHER_TARGET, "covers another target (host)");
        }
        checkValidity(failures, record.getValidFrom(), record.getValidUntil(), host, request.at(), zone);
        return failures.check(record.getTicketId(), RecordCheck.TICKET, null, false);
    }

    /** Whether the requester is on call at the request time; null when the host did not say. */
    static Boolean onCallAt(OnCallRecord record, Instant at) {
        if (record == null || record.getOnCall() == null) {
            return null;
        }
        if (!record.getOnCall()) {
            return false;
        }
        if (at != null && ((record.getStartsAt() != null && at.isBefore(record.getStartsAt()))
                || (record.getEndsAt() != null && !at.isBefore(record.getEndsAt())))) {
            return false;
        }
        return true;
    }

    private static void checkValidity(Failures failures, Instant from, Instant until, Set<String> host, Instant at,
                                      ZoneId zone) {
        boolean outside = at != null && ((from != null && at.isBefore(from)) || (until != null && !at.isBefore(until)));
        if (outside) {
            failures.add(PolicyReason.EXPIRED, "valid " + window(from, until, at, zone) + ", the request is outside it");
        }
        else if (host.contains("VALIDITY")) {
            failures.add(PolicyReason.EXPIRED, "is outside its validity (host)");
        }
    }

    /**
     * The items the session exported to the request's target within the record's validity before this request, as
     * its allowed decisions say; null when the request has no target to count by.
     */
    private static Integer usedInSession(Request request, Instant from, Instant until) {
        if (request.target() == null) {
            return null;
        }
        int used = 0;
        for (SessionDecisionRecord decision : request.sessionDecisions()) {
            if (decision == null || decision.items() == null || !request.target().equals(decision.target())
                    || !ALLOW.equalsIgnoreCase(String.valueOf(decision.outcome()))) {
                continue;
            }
            Instant at = decision.at();
            if (at != null && ((request.at() != null && !at.isBefore(request.at()))
                    || (from != null && at.isBefore(from)) || (until != null && !at.isBefore(until)))) {
                continue;
            }
            used += decision.items();
        }
        return used;
    }

    private static PolicySatisfaction satisfaction(FrictionProfile profile, Request request,
                                                   List<RecordCheck> approvals, List<RecordCheck> tickets,
                                                   Boolean onCall) {
        List<CompanyPolicy> policies = profile.getPolicies() == null ? List.of()
                : profile.getPolicies().stream().filter(policy -> policy != null).toList();
        if (policies.isEmpty()) {
            return PolicySatisfaction.UNKNOWN;
        }
        List<String> policyIds = policies.stream().map(CompanyPolicy::getPolicyId).filter(StringUtils::hasText).toList();
        List<PolicySatisfaction> results = policies.stream()
                .map(policy -> satisfaction(policy, profile, request, approvals, tickets, onCall))
                .toList();
        Optional<PolicySatisfaction> unsatisfied = results.stream()
                .filter(result -> Boolean.FALSE.equals(result.satisfied())).findFirst();
        if (unsatisfied.isPresent()) {
            PolicySatisfaction first = unsatisfied.get();
            return new PolicySatisfaction(false, first.reason(), first.recordIds(), first.detail(), policyIds);
        }
        Optional<PolicySatisfaction> undecided = results.stream()
                .filter(result -> result.satisfied() == null).findFirst();
        if (undecided.isPresent()) {
            return new PolicySatisfaction(null, null, undecided.get().recordIds(), undecided.get().detail(),
                    policyIds);
        }
        List<String> recordIds = results.stream().flatMap(result -> result.recordIds().stream()).distinct().toList();
        String detail = results.stream().map(PolicySatisfaction::detail).filter(StringUtils::hasText)
                .collect(Collectors.joining("; "));
        return new PolicySatisfaction(true, null, recordIds, detail, policyIds);
    }

    private static PolicySatisfaction satisfaction(CompanyPolicy policy, FrictionProfile profile, Request request,
                                                   List<RecordCheck> approvals, List<RecordCheck> tickets,
                                                   Boolean onCall) {
        String requirement = upper(policy.getRequirement());
        String requiredKind = upper(policy.getRequiredTicketKind());
        List<String> policyIds = StringUtils.hasText(policy.getPolicyId()) ? List.of(policy.getPolicyId()) : List.of();
        String target = targetName(profile, request);
        List<RecordCheck> fitting = tickets.stream()
                .filter(check -> ticketKindFits(profile, check.recordId(), requiredKind))
                .toList();
        Optional<RecordCheck> validTicket = fitting.stream().filter(RecordCheck::valid).findFirst();
        // What could satisfy the policy but cannot be checked; with it the policy is not known, not unsatisfied.
        List<String> unknown = new ArrayList<>();
        List<String> unknownIds = new ArrayList<>();

        if ("APPROVAL".equals(requirement)) {
            Optional<RecordCheck> approval = approvals.stream().filter(RecordCheck::valid).findFirst();
            if (approval.isPresent()) {
                return satisfied(approvalCover(profile, approval.get(), request), List.of(approval.get().recordId()),
                        policyIds);
            }
            approvals.stream().filter(RecordCheck::undecided).findFirst().ifPresent(check -> {
                unknown.add("approval " + check.recordId() + ": " + String.join("; ", check.unknowns()));
                unknownIds.add(check.recordId());
            });
            if (approvals.isEmpty() && !checked(profile, FrictionProfile.RECORD_APPROVAL)) {
                unknown.add("approvals were not looked up");
            }
        }
        else if ("TICKET".equals(requirement)) {
            if (validTicket.isPresent()) {
                return satisfied("ticket " + validTicket.get().recordId() + " covers "
                                + ticketTarget(profile, validTicket.get().recordId(), target),
                        List.of(validTicket.get().recordId()), policyIds);
            }
            if (tickets.isEmpty() && !checked(profile, FrictionProfile.RECORD_TICKET)) {
                unknown.add("tickets were not looked up");
            }
        }
        else {
            return new PolicySatisfaction(null, null, List.of(), null, policyIds);
        }

        List<PolicyException> exceptions = policy.getExceptions() == null ? List.of() : policy.getExceptions();
        for (PolicyException exception : exceptions) {
            ExceptionCheck check = exceptionCheck(exception, profile, request, validTicket, onCall, target);
            if (check.met() != null) {
                List<String> ids = "TICKET_WHILE_ON_CALL".equals(upper(exception.getKind())) && validTicket.isPresent()
                        ? List.of(validTicket.get().recordId()) : List.of();
                return satisfied(check.met(), ids, policyIds);
            }
            if (check.unknown() != null) {
                unknown.add(check.unknown());
            }
        }
        if (!unknown.isEmpty()) {
            return new PolicySatisfaction(null, null, unknownIds, "not known: " + String.join("; ", unknown),
                    policyIds);
        }

        if ("APPROVAL".equals(requirement)) {
            Optional<RecordCheck> closest = closest(approvals);
            if (closest.isPresent()) {
                return unsatisfied(closest.get(), "approval", policyIds);
            }
            boolean ticketException = exceptions.stream()
                    .anyMatch(exception -> "TICKET_WHILE_ON_CALL".equals(upper(exception.getKind())));
            if (ticketException && validTicket.isPresent() && !Boolean.TRUE.equals(onCall)) {
                return new PolicySatisfaction(false, PolicyReason.TICKET_WITHOUT_ON_CALL,
                        List.of(validTicket.get().recordId()),
                        "ticket " + validTicket.get().recordId() + " covers "
                                + ticketTarget(profile, validTicket.get().recordId(), target)
                                + ", but the requester is not on call", policyIds);
            }
            return new PolicySatisfaction(false, PolicyReason.NO_RECORD, List.of(), "no approval for " + target,
                    policyIds);
        }
        Optional<RecordCheck> closest = closest(fitting);
        if (closest.isPresent()) {
            return unsatisfied(closest.get(), "ticket", policyIds);
        }
        Optional<RecordCheck> otherKind = closest(tickets);
        if (otherKind.isPresent() && requiredKind != null) {
            return new PolicySatisfaction(false, PolicyReason.NO_RECORD, List.of(otherKind.get().recordId()),
                    "ticket " + otherKind.get().recordId() + " is not a " + requiredKind + " ticket", policyIds);
        }
        return new PolicySatisfaction(false, PolicyReason.NO_RECORD, List.of(),
                "no " + (requiredKind != null ? requiredKind + " " : "") + "ticket covers " + target, policyIds);
    }

    /** An exception that holds (in words), one a fact it needs is not known for (what), or neither. */
    private record ExceptionCheck(String met, String unknown) {

        static final ExceptionCheck NOT_MET = new ExceptionCheck(null, null);

        static ExceptionCheck met(String words) {
            return new ExceptionCheck(words, null);
        }

        static ExceptionCheck unknown(String what) {
            return new ExceptionCheck(null, what);
        }
    }

    /**
     * Whether the exception holds. A fact the exception needs that the host did not look up, or a number the request
     * does not state, leaves it not known rather than not met (P2 correction 3).
     */
    private static ExceptionCheck exceptionCheck(PolicyException exception, FrictionProfile profile, Request request,
                                                 Optional<RecordCheck> validTicket, Boolean onCall, String target) {
        String kind = upper(exception.getKind());
        AssignmentRecord assignment = profile.getAssignment();
        if ("ASSIGNED".equals(kind) || ACCOUNT_MANAGER.equals(kind)) {
            if (assignment == null || assignment.getAssigned() == null) {
                return checked(profile, FrictionProfile.RECORD_ASSIGNMENT) ? ExceptionCheck.NOT_MET
                        : ExceptionCheck.unknown("the assignment to " + target + " was not looked up");
            }
        }
        if ("ASSIGNED".equals(kind)) {
            // An account manager is a relation to a customer, not an assignment to a project.
            if (!assignment.getAssigned()
                    || ACCOUNT_MANAGER.equalsIgnoreCase(String.valueOf(assignment.getResponsibility()))) {
                return ExceptionCheck.NOT_MET;
            }
            if (exception.getLimit() == null) {
                return ExceptionCheck.met("assigned to " + target);
            }
            Integer items = request.items();
            if (items == null) {
                return ExceptionCheck.unknown("assigned to " + target + ", but the request does not state its item "
                        + "count against the assigned limit of " + number(exception.getLimit()));
            }
            if (items > exception.getLimit()) {
                return ExceptionCheck.NOT_MET;
            }
            return ExceptionCheck.met("assigned to " + target + ", " + number(items)
                    + " items within the assigned limit of " + number(exception.getLimit()));
        }
        if (ACCOUNT_MANAGER.equals(kind)) {
            return assignment.getAssigned()
                    && ACCOUNT_MANAGER.equalsIgnoreCase(String.valueOf(assignment.getResponsibility()))
                    ? ExceptionCheck.met("account manager of " + target) : ExceptionCheck.NOT_MET;
        }
        if ("RECENT_WORK".equals(kind)) {
            AccessHistoryRecord history = profile.getAccessHistory();
            if (history == null) {
                return checked(profile, FrictionProfile.RECORD_ACCESS_HISTORY) ? ExceptionCheck.NOT_MET
                        : ExceptionCheck.unknown("the work history on " + target + " was not looked up");
            }
            if (history.getDays() == null) {
                return ExceptionCheck.unknown("the work history on " + target + " gives no day count");
            }
            if (history.getDays() <= 0) {
                return ExceptionCheck.NOT_MET;
            }
            if (exception.getLimit() != null && history.getWindowDays() != null
                    && history.getWindowDays() > exception.getLimit()) {
                return ExceptionCheck.NOT_MET;
            }
            return ExceptionCheck.met("worked on " + target + " on " + history.getDays() + " of the last "
                    + (history.getWindowDays() != null ? history.getWindowDays() : exception.getLimit()) + " days");
        }
        if ("TICKET_WHILE_ON_CALL".equals(kind)) {
            if (validTicket.isEmpty()) {
                return (profile.getTicketRecords() == null || profile.getTicketRecords().isEmpty())
                        && !checked(profile, FrictionProfile.RECORD_TICKET)
                        ? ExceptionCheck.unknown("tickets were not looked up") : ExceptionCheck.NOT_MET;
            }
            if (onCall == null) {
                return ExceptionCheck.unknown("ticket " + validTicket.get().recordId() + " covers "
                        + ticketTarget(profile, validTicket.get().recordId(), target)
                        + ", but whether the requester is on call is not reported");
            }
            return onCall
                    ? ExceptionCheck.met("ticket " + validTicket.get().recordId() + " covers "
                    + ticketTarget(profile, validTicket.get().recordId(), target) + " and the requester is on call")
                    : ExceptionCheck.NOT_MET;
        }
        return ExceptionCheck.NOT_MET;
    }

    private static boolean ticketKindFits(FrictionProfile profile, String ticketId, String requiredKind) {
        if (requiredKind == null) {
            return true;
        }
        String kind = profile.getTicketRecords().stream()
                .filter(record -> record != null && ticketId.equals(record.getTicketId()))
                .findFirst()
                .map(record -> upper(record.getKind()))
                .orElse(null);
        // A ticket whose kind the host does not state is judged by the host's own verdict on it.
        return kind == null || kind.equals(requiredKind);
    }

    private static String approvalCover(FrictionProfile profile, RecordCheck check, Request request) {
        ApprovalRecord record = profile.getApprovalRecords().stream()
                .filter(approval -> approval != null && check.recordId().equals(approval.getApprovalId()))
                .findFirst().orElse(null);
        StringBuilder text = new StringBuilder("approval ").append(check.recordId());
        if (record != null && StringUtils.hasText(record.getPurpose())) {
            text.append(' ').append(record.getPurpose());
        }
        if (record != null && record.getMaxItems() != null) {
            text.append(" up to ").append(number(record.getMaxItems()));
            if (request.items() != null) {
                text.append(", requested ").append(number(request.items()));
            }
            if (check.usedBefore() != null && check.usedBefore() > 0) {
                text.append(" with ").append(number(check.usedBefore())).append(" already exported");
            }
        }
        if (record != null && record.getDecidedAt() != null) {
            text.append(", decided before the request");
        }
        else {
            text.append(", decision time not recorded");
        }
        return text.toString();
    }

    private static PolicySatisfaction satisfied(String detail, List<String> recordIds, List<String> policyIds) {
        return new PolicySatisfaction(true, null, recordIds, detail, policyIds);
    }

    private static PolicySatisfaction unsatisfied(RecordCheck check, String noun, List<String> policyIds) {
        return new PolicySatisfaction(false, check.reason(), List.of(check.recordId()),
                noun + " " + check.recordId() + " " + String.join("; ", check.notes()), policyIds);
    }

    /** The record that comes closest to covering: the fewest failures, then the host's order. */
    private static Optional<RecordCheck> closest(List<RecordCheck> checks) {
        return checks.stream().min(Comparator.comparingInt(check -> check.failures().size()));
    }

    /** What a ticket covers as its record states it (a customer's project), else the request's target. */
    private static String ticketTarget(FrictionProfile profile, String ticketId, String target) {
        return profile.getTicketRecords().stream()
                .filter(record -> record != null && ticketId.equals(record.getTicketId())
                        && StringUtils.hasText(record.getTarget()))
                .map(TicketRecord::getTarget)
                .findFirst().orElse(target);
    }

    /** The target as the host names it in its records, else the request's own target. */
    static String targetName(FrictionProfile profile, Request request) {
        if (profile.getAssignment() != null && StringUtils.hasText(profile.getAssignment().getTarget())) {
            return profile.getAssignment().getTarget();
        }
        if (profile.getAccessHistory() != null && StringUtils.hasText(profile.getAccessHistory().getTarget())) {
            return profile.getAccessHistory().getTarget();
        }
        // Without a host record target, the values of the request path are the requester's text (N-INJ-1).
        return "this target";
    }

    static String number(int value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    /** A validity window on the event clock and where its ends are from the request (W3-13). */
    static String window(Instant from, Instant until, Instant request, ZoneId zone) {
        String relative = RelativeTime.window(from, until, request);
        return (from != null ? WALL_CLOCK.format(from.atZone(zone)) : "") + ".."
                + (until != null ? WALL_CLOCK.format(until.atZone(zone)) : "")
                + (relative != null ? " (" + relative + ")" : "");
    }

    /** A time on the event clock and how far it is from the request (W3-13). */
    static String wallClock(Instant at, Instant request, ZoneId zone) {
        String relative = RelativeTime.of(at, request);
        return WALL_CLOCK.format(at.atZone(zone)) + (relative != null ? " (" + relative + ")" : "");
    }

    private static String upper(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : null;
    }

    private static Set<String> upper(List<String> values) {
        Set<String> upper = new LinkedHashSet<>();
        if (values != null) {
            for (String value : values) {
                String word = upper(value);
                if (word != null) {
                    upper.add(word);
                }
            }
        }
        return upper;
    }

    /** A record's failures in the order of {@link PolicyReason}, each reason once with its first note. */
    private static final class Failures {

        private final List<PolicyReason> reasons = new ArrayList<>();
        private final List<String> notes = new ArrayList<>();
        private final List<String> unknowns = new ArrayList<>();

        void add(PolicyReason reason, String note) {
            if (!reasons.contains(reason)) {
                reasons.add(reason);
                notes.add(note);
            }
        }

        void unknown(String note) {
            if (!unknowns.contains(note)) {
                unknowns.add(note);
            }
        }

        RecordCheck check(String recordId, String kind, Integer usedBefore, boolean claimFalse) {
            List<Integer> order = new ArrayList<>();
            for (int index = 0; index < reasons.size(); index++) {
                order.add(index);
            }
            order.sort(Comparator.comparingInt(index -> reasons.get(index).ordinal()));
            List<PolicyReason> sortedReasons = order.stream().map(reasons::get).toList();
            List<String> sortedNotes = order.stream().map(notes::get).toList();
            return new RecordCheck(recordId, kind, sortedReasons.isEmpty() && unknowns.isEmpty(), sortedReasons,
                    sortedNotes, usedBefore, claimFalse, unknowns);
        }
    }
}
