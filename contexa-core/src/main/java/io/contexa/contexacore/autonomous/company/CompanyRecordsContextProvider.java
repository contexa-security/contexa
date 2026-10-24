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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
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
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AccessHistoryRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AssignmentRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.CompanyPolicy;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.OnCallRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PolicyException;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.TicketRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.TravelRecord;
import io.contexa.contexacore.autonomous.context.enricher.FrictionContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.RecordsHolder;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import io.contexa.contexacore.autonomous.context.support.ActionFamilyResolver;
import io.contexa.contexacore.autonomous.context.support.NetworkBlocks;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Judges each request with the company records of the person who answers for it (docs/agent OC-2): the person's own
 * request, or for an agent's request the person it acts for or its sponsor ({@link RecordsHolder}). It runs for a
 * request a company rule covers ({@link Policy}: its actions and resource categories), for a person the company knows
 * ({@link Person}), and states on the request's context what the records say about it:
 * <ul>
 *     <li>the rules that cover it, with whether each needs a covering record here (the company's own check);</li>
 *     <li>the record that comes closest to covering it among the person's approvals and tickets, with the conditions
 *     it fails: approved by the requester, another target, another action, more items, outside its validity, not in an
 *     approved or active state; a ticket the requester names in the request, and whether it exists;</li>
 *     <li>the assignment to the target (or account management of it), the days worked on it, whether the person is on
 *     call, and the zone of the request's network: a company network, the network of the person's registered trip at
 *     that time, or external.</li>
 * </ul>
 * Targets are the request's resource scope as the application states it, never the request's own text. A kind of record
 * the company does not integrate is not looked up, so it stays not known rather than none found. What the records mean
 * for the request is the decision's to weigh; this provider states facts and the company's own check only.
 * <p>
 * An application's own {@code FrictionContextProvider} runs beside it and adds its records to the same context.
 */
public class CompanyRecordsContextProvider implements FrictionContextProvider {

    /** The zone of a request from the network of the person's registered trip. */
    public static final String TRAVEL_ZONE = "TRAVEL";
    /** The zone of a request from outside every company network and trip, when the company states its networks. */
    public static final String EXTERNAL_ZONE = "EXTERNAL";
    /** The event metadata key of a record the requester names in the request (a ticket key it claims covers it). */
    public static final String CLAIMED_RECORD = "claimedRecord";

    static final Set<String> APPROVED_STATES = Set.of("APPROVED", "GRANTED", "COMPLETED");
    static final Set<String> ACTIVE_TICKET_STATES = Set.of("OPEN", "APPROVED", "ACTIVE", "IN_PROGRESS");
    static final int DEFAULT_HISTORY_DAYS = 90;
    static final String LOOKED_UP = "Company facts of this request were looked up in the company records.";
    static final String NOT_LOOKED_UP = "Company facts of this request were not looked up: the request time is "
            + "unknown.";

    static final String APPROVER = "APPROVER";
    static final String TARGET = "TARGET";
    static final String PURPOSE = "PURPOSE";
    static final String ITEMS = "ITEMS";
    static final String VALIDITY = "VALIDITY";
    static final String STATUS = "STATUS";
    static final String NO_TICKET = "NO_TICKET";

    /** The order the looked-up kinds are stated in. */
    private static final List<CompanyRecordKind> CHECK_ORDER = List.of(CompanyRecordKind.ASSIGNMENT,
            CompanyRecordKind.APPROVAL, CompanyRecordKind.TICKET, CompanyRecordKind.ON_CALL,
            CompanyRecordKind.ACCESS_HISTORY, CompanyRecordKind.TRAVEL);

    private final CompanyRecordStore store;

    public CompanyRecordsContextProvider(CompanyRecordStore store) {
        if (store == null) {
            throw new IllegalArgumentException("A company record store is required");
        }
        this.store = store;
    }

    @Override
    public void enrich(SecurityEvent event, CanonicalSecurityContext context) {
        if (event == null || context == null) {
            return;
        }
        RecordsHolder holder = RecordsHolder.of(event);
        if (holder == null) {
            return;
        }
        String tenant = tenant(context);
        CompanyRecordSet company = company(tenant);
        Request request = Request.of(event, context);
        List<Policy> applying = company.policies().stream().filter(policy -> applies(policy, request)).toList();
        if (applying.isEmpty()) {
            return;
        }
        CompanyRecordSet person = store.ofSubject(tenant, holder.id());
        if (tenant != null) {
            person = person.plus(store.ofSubject(null, holder.id()));
        }
        if (person.people().isEmpty()) {
            return;
        }
        if (request.at() == null) {
            profile(context).setSummary(NOT_LOOKED_UP);
            return;
        }
        Set<CompanyRecordKind> integrated = new LinkedHashSet<>(company.integratedKinds());
        integrated.addAll(person.integratedKinds());
        new Evaluation(holder.id(), person, company, integrated, applying, request).applyTo(context);
        holder.stateOn(context);
    }

    /** The tenant's rules and networks, else the deployment's own; the kinds both integrate. */
    private CompanyRecordSet company(@Nullable String tenant) {
        CompanyRecordSet own = store.company(tenant);
        if (tenant == null) {
            return own;
        }
        CompanyRecordSet shared = store.company(null);
        List<String> sources = Stream.concat(own.sources().stream(), shared.sources().stream()).distinct().toList();
        return new CompanyRecordSet(null, sources, null, null, null, null, null, null, null,
                own.policies().isEmpty() ? shared.policies() : own.policies(),
                own.networks().isEmpty() ? shared.networks() : own.networks());
    }

    static boolean applies(Policy policy, Request request) {
        return (policy.actions().isEmpty() || (request.action() != null && containsIgnoreCase(policy.actions(),
                request.action())))
                && (policy.categories().isEmpty() || (request.category() != null
                && containsIgnoreCase(policy.categories(), request.category())));
    }

    /**
     * The request as the records are matched with it.
     *
     * @param action   the action the application declares for the request, else its action family; null unknown
     * @param category the resource category the application declares
     * @param scope    the values of the resource scope the application states ({@code HX-310} of
     *                 {@code projectKey=HX-310}): the key the records name the target by
     * @param named    the values of the URL template's variables (the record the request names)
     * @param claimed  a record the requester names in the request as covering it
     */
    record Request(@Nullable Instant at, @Nullable String clientIp, @Nullable String action,
                   @Nullable String category, List<String> scope, List<String> named, @Nullable Integer items,
                   @Nullable String claimed) {

        static Request of(SecurityEvent event, CanonicalSecurityContext context) {
            Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
            CanonicalSecurityContext.Resource resource = context.getResource();
            String category = resource != null ? text(resource.getResourceCategory()) : null;
            if (category == null) {
                category = firstText(metadata.get("protectableResourceCategory"), metadata.get("resourceCategory"));
            }
            List<String> scope = resource != null ? values(resource.getScope()) : List.of();
            List<String> named = resource != null
                    ? values(BaselineViewCalculator.target(resource.getPathFamily(), resource.getRequestPath()))
                    : List.of();
            return new Request(event.getTimestamp(), text(event.getSourceIp()), declaredAction(metadata), category, scope,
                    named, resource != null ? resource.getRequestedItems() : null,
                    text(metadata.get(CLAIMED_RECORD)));
        }

        /** The record target: the first value of the resource scope; null when the application states none. */
        @Nullable
        String target() {
            return scope.isEmpty() ? null : scope.get(0);
        }
    }

    /** The action the application declares on the request or its protected method, else the inferred family. */
    @Nullable
    static String declaredAction(Map<String, Object> metadata) {
        ActionFamilyResolver.Resolution resolution = ActionFamilyResolver.resolve(metadata);
        if (resolution.family() == ActionFamily.UNKNOWN) {
            return null;
        }
        if (ActionFamilyResolver.HOST.equals(resolution.grade())) {
            String declared = text(metadata.get(resolution.sourceKey()));
            if (declared != null) {
                return declared.toUpperCase(Locale.ROOT);
            }
        }
        return resolution.family().name();
    }

    /** One request checked against the person's records. */
    private static final class Evaluation {

        private final String subject;
        private final CompanyRecordSet person;
        private final CompanyRecordSet company;
        private final Set<CompanyRecordKind> integrated;
        private final List<Policy> applying;
        private final Request request;
        private final Instant at;
        private final LocalDate day;
        private final Set<String> self = new LinkedHashSet<>();
        private final Set<CompanyRecordKind> checked = new LinkedHashSet<>();

        private AssignmentRecord assignment;
        private Check<Approval> approval;
        private Check<Ticket> ticket;
        private TicketRecord claimedTicket;
        private OnCallRecord onCall;
        private AccessHistoryRecord history;
        private TravelRecord trip;
        private String zone;
        private Integer historyWindow;

        Evaluation(String subject, CompanyRecordSet person, CompanyRecordSet company,
                   Set<CompanyRecordKind> integrated, List<Policy> applying, Request request) {
            this.subject = subject;
            this.person = person;
            this.company = company;
            this.integrated = integrated;
            this.applying = applying;
            this.request = request;
            this.at = request.at();
            this.day = LocalDate.ofInstant(at, ZoneOffset.UTC);
            self.add(subject);
            person.people().stream().map(Person::companyId).filter(Objects::nonNull).map(String::trim)
                    .filter(id -> !id.isEmpty()).forEach(self::add);
        }

        void applyTo(CanonicalSecurityContext context) {
            Set<CompanyRecordKind> consulted = consulted(applying);
            String target = request.target();
            if (looksUp(consulted, CompanyRecordKind.ASSIGNMENT) && target != null) {
                assignment = assignment(target);
                checked.add(CompanyRecordKind.ASSIGNMENT);
            }
            if (looksUp(consulted, CompanyRecordKind.APPROVAL) && target != null) {
                approval = closest(person.approvals().stream().map(record -> checkApproval(record, target)).toList());
                checked.add(CompanyRecordKind.APPROVAL);
            }
            if (looksUp(consulted, CompanyRecordKind.TICKET) && target != null) {
                ticket = closest(person.tickets().stream().map(record -> checkTicket(record, target)).toList());
                claimedTicket = claimed(target);
                checked.add(CompanyRecordKind.TICKET);
            }
            if (looksUp(consulted, CompanyRecordKind.ON_CALL)) {
                onCall = onCall();
                checked.add(CompanyRecordKind.ON_CALL);
            }
            if (looksUp(consulted, CompanyRecordKind.ACCESS_HISTORY) && target != null) {
                historyWindow = historyWindow(applying);
                history = history(target, historyWindow);
                checked.add(CompanyRecordKind.ACCESS_HISTORY);
            }
            if (consulted.contains(CompanyRecordKind.TRAVEL)) {
                network();
                if (integrated.contains(CompanyRecordKind.TRAVEL)) {
                    checked.add(CompanyRecordKind.TRAVEL);
                }
            }
            List<CompanyPolicy> policies = applying.stream().map(this::policy).toList();
            apply(context, policies);
        }

        private boolean looksUp(Set<CompanyRecordKind> consulted, CompanyRecordKind kind) {
            return consulted.contains(kind) && integrated.contains(kind);
        }

        private AssignmentRecord assignment(String target) {
            boolean accountManager = applying.stream().flatMap(policy -> policy.exceptions().stream())
                    .anyMatch(rule -> CompanyRecordSet.ACCOUNT_MANAGER.equals(upper(rule.kind())));
            if (accountManager) {
                // Account management is a relation to the record the request names (a customer), or to its scope.
                List<String> names = Stream.concat(request.named().stream(), request.scope().stream()).toList();
                Assignment found = first(person.assignments(), record -> record.accountManager()
                        && names.contains(record.target()) && record.validOn(day));
                return AssignmentRecord.builder()
                        .target(found != null ? found.target() : request.named().isEmpty() ? target
                                : request.named().get(0))
                        .assigned(found != null)
                        .responsibility(CompanyRecordSet.ACCOUNT_MANAGER)
                        .build();
            }
            Assignment found = first(person.assignments(), record -> !record.accountManager()
                    && target.equals(record.target()) && record.validOn(day));
            return AssignmentRecord.builder()
                    .target(target)
                    .assigned(found != null)
                    .responsibility(found != null ? found.responsibility() : null)
                    .build();
        }

        private Check<Approval> checkApproval(Approval record, String target) {
            List<String> mismatches = new ArrayList<>();
            if (selfApproved(record.approver())) {
                mismatches.add(APPROVER);
            }
            if (!target.equals(record.target())) {
                mismatches.add(TARGET);
            }
            if (actionNotCovered(record.actions())) {
                mismatches.add(PURPOSE);
            }
            if (record.maxItems() != null && request.items() != null && request.items() > record.maxItems()) {
                mismatches.add(ITEMS);
            }
            if (outside(record.validFrom(), record.validUntil())) {
                mismatches.add(VALIDITY);
            }
            String status = upper(record.status());
            if (status != null && !APPROVED_STATES.contains(status)) {
                mismatches.add(STATUS);
            }
            return new Check<>(record, mismatches);
        }

        private Check<Ticket> checkTicket(Ticket record, String target) {
            List<String> mismatches = new ArrayList<>();
            if (selfApproved(record.approver())) {
                mismatches.add(APPROVER);
            }
            if (!target.equals(record.target())) {
                mismatches.add(TARGET);
            }
            if (actionNotCovered(record.actions())) {
                mismatches.add(PURPOSE);
            }
            if (outside(record.validFrom(), record.validUntil())) {
                mismatches.add(VALIDITY);
            }
            String status = upper(record.status());
            if (status != null && !ACTIVE_TICKET_STATES.contains(status)) {
                mismatches.add(STATUS);
            }
            return new Check<>(record, mismatches);
        }

        /** A ticket the requester names in the request: checked like the others, or stated as not existing. */
        @Nullable
        private TicketRecord claimed(String target) {
            String claimed = request.claimed();
            if (claimed == null) {
                return null;
            }
            Ticket found = first(person.tickets(), record -> claimed.equals(record.id()));
            if (found == null) {
                return TicketRecord.builder()
                        .ticketId(claimed)
                        .claimedByRequester(Boolean.TRUE)
                        .exists(Boolean.FALSE)
                        .hostCovers(false)
                        .hostMismatches(new ArrayList<>(List.of(NO_TICKET)))
                        .build();
            }
            TicketRecord record = ticketRecord(checkTicket(found, target), target);
            record.setTicketId(claimed);
            record.setClaimedByRequester(Boolean.TRUE);
            record.setExists(Boolean.TRUE);
            return record;
        }

        private OnCallRecord onCall() {
            OnCall shift = person.onCall().stream()
                    .filter(record -> (record.startsAt() == null || !at.isBefore(record.startsAt()))
                            && (record.endsAt() == null || at.isBefore(record.endsAt())))
                    .min(Comparator.comparing(OnCall::startsAt, Comparator.nullsFirst(Comparator.naturalOrder())))
                    .orElse(null);
            if (shift == null) {
                return OnCallRecord.builder().onCall(false).build();
            }
            return OnCallRecord.builder()
                    .onCall(true)
                    .rosterId(shift.id())
                    .team(shift.team())
                    .startsAt(shift.startsAt())
                    .endsAt(shift.endsAt())
                    .build();
        }

        private AccessHistoryRecord history(String target, int window) {
            List<LocalDate> days = workDays(target, window);
            return AccessHistoryRecord.builder()
                    .target(target)
                    .days(days.size())
                    .windowDays(window)
                    .lastAccessDate(days.isEmpty() ? null : days.get(days.size() - 1).toString())
                    .build();
        }

        /** The distinct days worked on the target within the window before the request's day, in order. */
        private List<LocalDate> workDays(String target, int window) {
            LocalDate from = day.minusDays(window);
            return person.accessDays().stream()
                    .filter(record -> target.equals(record.target()) && record.day() != null
                            && !record.day().isBefore(from) && record.day().isBefore(day))
                    .map(AccessDay::day)
                    .distinct()
                    .sorted()
                    .toList();
        }

        /** The zone of the request's network: a company network, the person's registered trip, or external. */
        private void network() {
            String address = request.clientIp();
            if (address == null) {
                return;
            }
            for (NetworkZone network : company.networks()) {
                if (Boolean.TRUE.equals(NetworkBlocks.contains(network.cidr(), address))) {
                    zone = network.zone().trim().toUpperCase(Locale.ROOT);
                    return;
                }
            }
            if (integrated.contains(CompanyRecordKind.TRAVEL)) {
                Travel found = first(person.travel(), record -> !outside(record.validFrom(), record.validUntil())
                        && Boolean.TRUE.equals(NetworkBlocks.contains(record.network(), address)));
                if (found != null) {
                    zone = TRAVEL_ZONE;
                    trip = TravelRecord.builder()
                            .planId(found.id())
                            .city(found.city())
                            .country(found.country())
                            .network(found.network())
                            .build();
                    return;
                }
            }
            if (!company.networks().isEmpty()) {
                zone = EXTERNAL_ZONE;
            }
        }

        private CompanyPolicy policy(Policy policy) {
            List<PolicyException> exceptions = policy.exceptions().stream()
                    .map(rule -> PolicyException.builder().kind(upper(rule.kind())).limit(rule.limit()).build())
                    .toList();
            return CompanyPolicy.builder()
                    .policyId(policy.id())
                    .statement(policy.statement())
                    .requirement(upper(policy.requirement()))
                    .requiredTicketKind(upper(policy.requiredTicketKind()))
                    .exceptions(new ArrayList<>(exceptions))
                    .hostRequires(requires(policy))
                    .build();
        }

        /**
         * The company's own check of the rule: whether the request needs a covering record, that is whether none of
         * its exceptions holds. Null when an exception rests on a record that was not looked up and none holds.
         */
        @Nullable
        private Boolean requires(Policy policy) {
            boolean unknown = false;
            for (Policy.Rule rule : policy.exceptions()) {
                Boolean holds = exceptionHolds(rule);
                if (Boolean.TRUE.equals(holds)) {
                    return false;
                }
                unknown |= holds == null;
            }
            return unknown ? null : Boolean.TRUE;
        }

        @Nullable
        private Boolean exceptionHolds(Policy.Rule rule) {
            String kind = upper(rule.kind());
            if ("ASSIGNED".equals(kind) || CompanyRecordSet.ACCOUNT_MANAGER.equals(kind)) {
                if (assignment == null) {
                    return null;
                }
                boolean manager = CompanyRecordSet.ACCOUNT_MANAGER.equalsIgnoreCase(
                        String.valueOf(assignment.getResponsibility()));
                if (CompanyRecordSet.ACCOUNT_MANAGER.equals(kind)) {
                    return Boolean.TRUE.equals(assignment.getAssigned()) && manager;
                }
                if (!Boolean.TRUE.equals(assignment.getAssigned()) || manager) {
                    return false;
                }
                return rule.limit() == null || (request.items() != null && request.items() <= rule.limit());
            }
            if ("RECENT_WORK".equals(kind)) {
                if (history == null) {
                    return null;
                }
                int window = rule.limit() != null ? rule.limit() : historyWindow;
                return !workDays(history.getTarget(), window).isEmpty();
            }
            if ("TICKET_WHILE_ON_CALL".equals(kind)) {
                if (!checked.contains(CompanyRecordKind.TICKET) || onCall == null) {
                    return null;
                }
                return ticket != null && ticket.covers() && Boolean.TRUE.equals(onCall.getOnCall());
            }
            return false;
        }

        private void apply(CanonicalSecurityContext context, List<CompanyPolicy> policies) {
            FrictionProfile profile = profile(context);
            List<ApprovalRecord> approvals = new ArrayList<>();
            if (approval != null) {
                approvals.add(approvalRecord(approval, request.target()));
            }
            List<TicketRecord> tickets = new ArrayList<>();
            if (ticket != null) {
                tickets.add(ticketRecord(ticket, request.target()));
            }
            if (claimedTicket != null) {
                tickets.add(claimedTicket);
            }
            profile.setApprovalRecords(appended(profile.getApprovalRecords(), approvals));
            profile.setTicketRecords(appended(profile.getTicketRecords(), tickets));
            profile.setPolicies(appended(profile.getPolicies(), policies));
            profile.setCheckedRecordKinds(appended(profile.getCheckedRecordKinds(), CHECK_ORDER.stream()
                    .filter(checked::contains).map(CompanyRecordKind::name).toList()));
            if (onCall != null) {
                profile.setOnCall(onCall);
            }
            if (trip != null) {
                profile.setTravel(trip);
            }
            if (assignment != null) {
                profile.setAssignment(assignment);
            }
            if (history != null) {
                profile.setAccessHistory(history);
            }
            approvalState(profile, policies);
            profile.setSummary(LOOKED_UP);
            if (zone != null) {
                if (context.getLocation() == null) {
                    context.setLocation(new CanonicalSecurityContext.Location());
                }
                context.getLocation().setNetworkZone(zone);
            }
        }

        /**
         * Whether the rules need an approval here and whether one is there, as the company's own check says: under a
         * rule that needs an approval, the closest approval; under the others, a covering ticket is the approval.
         */
        private void approvalState(FrictionProfile profile, List<CompanyPolicy> policies) {
            Boolean required = null;
            for (CompanyPolicy policy : policies) {
                if (Boolean.TRUE.equals(policy.getHostRequires())) {
                    required = true;
                    break;
                }
                if (policy.getHostRequires() == null) {
                    required = null;
                    break;
                }
                required = false;
            }
            boolean approvalRule = checked.contains(CompanyRecordKind.APPROVAL) && policies.stream()
                    .anyMatch(policy -> "APPROVAL".equals(policy.getRequirement()));
            if (approvalRule) {
                boolean covered = approval != null && approval.covers();
                profile.setApprovalGranted(covered);
                profile.setApprovalStatus(covered ? "APPROVED" : "NO_COVERING_APPROVAL");
                if (required != null) {
                    profile.setApprovalRequired(required);
                    profile.setApprovalMissing(required && !covered);
                }
                if (covered) {
                    profile.setApprovalTicketId(approval.record().id());
                    Instant decided = approval.record().decidedAt();
                    if (decided != null && !decided.isAfter(at)) {
                        profile.setApprovalDecisionAgeMinutes((int) Duration.between(decided, at).toMinutes());
                    }
                }
                return;
            }
            if (required == null) {
                return;
            }
            boolean covered = ticket != null && ticket.covers();
            profile.setApprovalRequired(required);
            profile.setApprovalMissing(required && !covered);
            if (covered || required) {
                profile.setApprovalGranted(covered);
                profile.setApprovalStatus(covered ? "APPROVED" : "NO_COVERING_APPROVAL");
            }
            if (covered) {
                profile.setApprovalTicketId(ticket.record().id());
            }
        }

        private ApprovalRecord approvalRecord(Check<Approval> check, String target) {
            Approval record = check.record();
            return ApprovalRecord.builder()
                    .approvalId(record.id())
                    .status(check.fails(STATUS) ? null : upper(record.status()))
                    .approver(record.approver())
                    .purpose(record.purpose())
                    .target(check.fails(TARGET) ? null : target)
                    .maxItems(record.maxItems() != null && record.maxItems() > 0 ? record.maxItems() : null)
                    .usedItems(usedItems(record))
                    .validFrom(record.validFrom())
                    .validUntil(record.validUntil())
                    .decidedAt(record.decidedAt())
                    .recordedBy(record.recordedBy())
                    .recordedAt(record.recordedAt())
                    .hostCovers(check.covers())
                    .hostMismatches(new ArrayList<>(check.mismatches()))
                    .build();
        }

        private TicketRecord ticketRecord(Check<Ticket> check, String target) {
            Ticket record = check.record();
            return TicketRecord.builder()
                    .ticketId(record.id())
                    .kind(record.kind())
                    .approver(record.approver())
                    .purpose(record.purpose())
                    .target(check.fails(TARGET) ? null : target)
                    .validFrom(record.validFrom())
                    .validUntil(record.validUntil())
                    .recordedBy(record.recordedBy())
                    .recordedAt(record.recordedAt())
                    .hostCovers(check.covers())
                    .hostMismatches(new ArrayList<>(check.mismatches()))
                    .build();
        }

        /**
         * The items delivered under the approval before the request: the person's usage of its target within its
         * validity, when the application reports usage; null (not known) otherwise.
         */
        @Nullable
        private Integer usedItems(Approval record) {
            if (!Boolean.TRUE.equals(record.usageReported())) {
                return null;
            }
            Instant until = record.validUntil() != null && record.validUntil().isBefore(at) ? record.validUntil() : at;
            return person.usage().stream()
                    .filter(used -> Objects.equals(record.target(), used.target()) && used.at() != null
                            && (record.validFrom() == null || !used.at().isBefore(record.validFrom()))
                            && used.at().isBefore(until))
                    .mapToInt(Usage::items)
                    .sum();
        }

        private boolean selfApproved(@Nullable String approver) {
            return approver == null || approver.isBlank() || self.contains(approver.trim());
        }

        private boolean actionNotCovered(List<String> actions) {
            return !actions.isEmpty() && request.action() != null && !containsIgnoreCase(actions, request.action());
        }

        private boolean outside(@Nullable Instant from, @Nullable Instant until) {
            return (from != null && at.isBefore(from)) || (until != null && !at.isBefore(until));
        }
    }

    /** A record checked against the request: the conditions it fails. */
    private record Check<T>(T record, List<String> mismatches) {

        boolean covers() {
            return mismatches.isEmpty();
        }

        boolean fails(String condition) {
            return mismatches.contains(condition);
        }

        /** How far it is from covering; a record for another target ranks behind any for the same target. */
        int distance() {
            return mismatches.size() + (mismatches.contains(TARGET) ? 10 : 0);
        }
    }

    /** The first record that covers the request, else the closest one, the earlier one among equally close. */
    @Nullable
    private static <T> Check<T> closest(List<Check<T>> checks) {
        Check<T> closest = null;
        for (Check<T> check : checks) {
            if (check.covers()) {
                return check;
            }
            if (closest == null || check.distance() < closest.distance()) {
                closest = check;
            }
        }
        return closest;
    }

    /**
     * The kinds the rules check a request against: those a rule names, else those its requirement and exceptions rest
     * on, and the network zone with the person's trips.
     */
    static Set<CompanyRecordKind> consulted(List<Policy> policies) {
        Set<CompanyRecordKind> kinds = new LinkedHashSet<>();
        for (Policy policy : policies) {
            if (!policy.records().isEmpty()) {
                policy.records().stream().map(CompanyRecordKind::of).filter(Objects::nonNull).forEach(kinds::add);
                continue;
            }
            String requirement = upper(policy.requirement());
            if ("APPROVAL".equals(requirement)) {
                kinds.add(CompanyRecordKind.APPROVAL);
            }
            if ("TICKET".equals(requirement)) {
                kinds.add(CompanyRecordKind.TICKET);
            }
            for (Policy.Rule rule : policy.exceptions()) {
                switch (String.valueOf(upper(rule.kind()))) {
                    case "ASSIGNED", CompanyRecordSet.ACCOUNT_MANAGER -> kinds.add(CompanyRecordKind.ASSIGNMENT);
                    case "RECENT_WORK" -> kinds.add(CompanyRecordKind.ACCESS_HISTORY);
                    case "TICKET_WHILE_ON_CALL" -> {
                        kinds.add(CompanyRecordKind.TICKET);
                        kinds.add(CompanyRecordKind.ON_CALL);
                    }
                    default -> {
                    }
                }
            }
            kinds.add(CompanyRecordKind.TRAVEL);
        }
        return kinds;
    }

    /** The days of work history shown: a rule's own, else its RECENT_WORK limit, else 90. */
    static int historyWindow(List<Policy> policies) {
        for (Policy policy : policies) {
            if (policy.historyDays() != null) {
                return policy.historyDays();
            }
        }
        for (Policy policy : policies) {
            for (Policy.Rule rule : policy.exceptions()) {
                if ("RECENT_WORK".equals(upper(rule.kind())) && rule.limit() != null) {
                    return rule.limit();
                }
            }
        }
        return DEFAULT_HISTORY_DAYS;
    }

    private static FrictionProfile profile(CanonicalSecurityContext context) {
        if (context.getFrictionProfile() == null) {
            context.setFrictionProfile(new FrictionProfile());
        }
        return context.getFrictionProfile();
    }

    @Nullable
    private static String tenant(CanonicalSecurityContext context) {
        CanonicalSecurityContext.Actor actor = context.getActor();
        Map<String, Object> attributes = context.getAttributes() != null ? context.getAttributes() : Map.of();
        return firstText(actor != null ? actor.getTenantId() : null, attributes.get("tenantId"));
    }

    /** The values of {@code key=value} bindings separated by commas. */
    static List<String> values(@Nullable String bindings) {
        if (bindings == null || bindings.isBlank()) {
            return List.of();
        }
        return Arrays.stream(bindings.split(","))
                .map(binding -> binding.contains("=") ? binding.substring(binding.indexOf('=') + 1) : binding)
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toList());
    }

    @Nullable
    private static <T> T first(List<T> records, Predicate<T> fits) {
        return records.stream().filter(fits).findFirst().orElse(null);
    }

    private static <T> List<T> appended(@Nullable List<T> existing, List<T> added) {
        List<T> all = new ArrayList<>(existing == null ? List.of() : existing);
        all.addAll(added);
        return all;
    }

    private static boolean containsIgnoreCase(List<String> values, String value) {
        return values.stream().anyMatch(candidate -> candidate != null && candidate.trim().equalsIgnoreCase(value));
    }

    @Nullable
    static String upper(@Nullable String value) {
        return value == null || value.isBlank() ? null : value.trim().toUpperCase(Locale.ROOT);
    }

    @Nullable
    private static String firstText(Object... values) {
        for (Object value : values) {
            String text = text(value);
            if (text != null) {
                return text;
            }
        }
        return null;
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
