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

import io.contexa.contexacore.autonomous.context.support.NetworkBlocks;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Company records as the company's own systems hold them (docs/agent OC-2): who its people are, their assignments,
 * approvals, tickets, on-call shifts, business trips and work days, what the application delivered to them, the
 * company's rules and its networks. An integration puts them into Contexa (the admin API, or {@link CompanyRecordStore}
 * in the application), and {@link CompanyRecordsContextProvider} judges each request with the records of the person
 * who answers for it.
 * <p>
 * A person is named by the {@code subject} Contexa knows them by (the user id of their requests); targets by the key
 * the application states as the request's resource scope ({@code projectKey=HX-310} names {@code HX-310}); actions by
 * the action the application declares for the request ({@code @Protectable(actions = ...)}), else its action family.
 *
 * @param sources the kinds the company integrates (ASSIGNMENT, APPROVAL, TICKET, ON_CALL, TRAVEL, ACCESS_HISTORY):
 *                a kind integrated and empty for a person means "none found", a kind not integrated "not looked up";
 *                putting any record of a kind integrates that kind
 */
public record CompanyRecordSet(List<Person> people, List<String> sources, List<Assignment> assignments,
                               List<Approval> approvals, List<Ticket> tickets, List<OnCall> onCall,
                               List<Travel> travel, List<AccessDay> accessDays, List<Usage> usage,
                               List<Policy> policies, List<NetworkZone> networks) {

    public static final CompanyRecordSet EMPTY = new CompanyRecordSet(null, null, null, null, null, null, null, null,
            null, null, null);

    /** The responsibility of an assignment that makes the person the account manager of its target. */
    public static final String ACCOUNT_MANAGER = "ACCOUNT_MANAGER";

    public CompanyRecordSet {
        people = copy(people);
        sources = copy(sources);
        assignments = copy(assignments);
        approvals = copy(approvals);
        tickets = copy(tickets);
        onCall = copy(onCall);
        travel = copy(travel);
        accessDays = copy(accessDays);
        usage = copy(usage);
        policies = copy(policies);
        networks = copy(networks);
    }

    /** A person the company knows; {@code companyId} is how its records name the person (an approver, a requester). */
    public record Person(String subject, @Nullable String companyId, @Nullable String displayName) {

        public String key() {
            return subject;
        }
    }

    /**
     * A person's assignment to a target from {@code from} to {@code until} (days, both included; open when null). The
     * responsibility {@link #ACCOUNT_MANAGER} makes the person the account manager of the target.
     */
    public record Assignment(String subject, String target, @Nullable String responsibility,
                             @Nullable LocalDate from, @Nullable LocalDate until) {

        public String key() {
            return join(subject, target, responsibility, from);
        }

        boolean accountManager() {
            return ACCOUNT_MANAGER.equalsIgnoreCase(String.valueOf(responsibility));
        }

        boolean validOn(LocalDate day) {
            return (from == null || !from.isAfter(day)) && (until == null || !until.isBefore(day));
        }
    }

    /**
     * An approval of work on a target.
     *
     * @param actions       the actions it approves; empty approves any action on the target
     * @param maxItems      the most items it allows; null without a limit
     * @param usageReported whether the application reports what it delivers under approvals ({@link Usage}): then the
     *                      items already delivered under this one are counted, else they are not known
     * @param recordedBy    who wrote the record in the company's system (a person, an agent, a system); null unknown
     */
    public record Approval(String id, String subject, @Nullable String approver, @Nullable String target,
                           @Nullable String purpose, @Nullable List<String> actions, @Nullable Integer maxItems,
                           @Nullable String status, @Nullable Instant validFrom, @Nullable Instant validUntil,
                           @Nullable Instant decidedAt, @Nullable Boolean usageReported, @Nullable String recordedBy,
                           @Nullable Instant recordedAt) {

        public Approval {
            actions = actions == null ? List.of() : List.copyOf(actions);
        }

        public String key() {
            return id;
        }
    }

    /**
     * A ticket of the company's ticket system.
     *
     * @param kind    the kind as the ticket system names it (CHANGE, INCIDENT)
     * @param actions the actions its purpose covers; empty covers any action on the target
     */
    public record Ticket(String id, String subject, @Nullable String kind, @Nullable String approver,
                         @Nullable String target, @Nullable String purpose, @Nullable List<String> actions,
                         @Nullable String status, @Nullable Instant validFrom, @Nullable Instant validUntil,
                         @Nullable String recordedBy, @Nullable Instant recordedAt) {

        public Ticket {
            actions = actions == null ? List.of() : List.copyOf(actions);
        }

        public String key() {
            return id;
        }
    }

    /** An on-call shift from {@code startsAt} (included) to {@code endsAt} (excluded). */
    public record OnCall(String id, String subject, @Nullable String team, @Nullable Instant startsAt,
                         @Nullable Instant endsAt) {

        public String key() {
            return id;
        }
    }

    /** A registered business trip; {@code network} is the CIDR block the traveller works from. */
    public record Travel(String id, String subject, @Nullable String city, @Nullable String country,
                         @Nullable String network, @Nullable Instant validFrom, @Nullable Instant validUntil) {

        public String key() {
            return id;
        }
    }

    /** A day on which the person worked on the target. */
    public record AccessDay(String subject, String target, LocalDate day) {

        public String key() {
            return join(subject, target, day);
        }
    }

    /** Items the application delivered to the person from the target at a time (an export, a download). */
    public record Usage(@Nullable String id, String subject, String target, int items, Instant at) {

        public String key() {
            return id != null && !id.isBlank() ? id : join(subject, target, at);
        }
    }

    /**
     * A company rule.
     *
     * @param requirement        what covers a request under the rule: APPROVAL, or TICKET
     * @param requiredTicketKind the ticket kind the rule needs (CHANGE); null for any
     * @param actions            the actions it covers; empty for every action
     * @param categories         the resource categories it covers ({@code @Protectable(category = ...)}); empty for
     *                           every category
     * @param exceptions         when it needs no covering record: ASSIGNED (up to {@code limit} items when set),
     *                           ACCOUNT_MANAGER, RECENT_WORK (work on the target within {@code limit} days),
     *                           TICKET_WHILE_ON_CALL
     * @param records            the record kinds a request under the rule is checked against; empty for those its
     *                           requirement and exceptions name, with TRAVEL
     * @param historyDays        the days of work history shown for a request under the rule; null for the
     *                           RECENT_WORK limit, else 90
     */
    public record Policy(String id, @Nullable String statement, @Nullable String requirement,
                         @Nullable String requiredTicketKind, @Nullable List<String> actions,
                         @Nullable List<String> categories, @Nullable List<Rule> exceptions,
                         @Nullable List<String> records, @Nullable Integer historyDays) {

        public Policy {
            actions = actions == null ? List.of() : List.copyOf(actions);
            categories = categories == null ? List.of() : List.copyOf(categories);
            exceptions = exceptions == null ? List.of() : exceptions.stream().filter(Objects::nonNull).toList();
            records = records == null ? List.of() : List.copyOf(records);
        }

        public String key() {
            return id;
        }

        /** An exception of the rule. */
        public record Rule(String kind, @Nullable Integer limit) {
        }
    }

    /** A company network and its zone (CORPORATE, VPN, PARTNER). */
    public record NetworkZone(String cidr, String zone) {

        public String key() {
            return cidr;
        }
    }

    /** The records of both sets, this set's first. */
    public CompanyRecordSet plus(@Nullable CompanyRecordSet other) {
        if (other == null || other.isEmpty()) {
            return this;
        }
        if (isEmpty()) {
            return other;
        }
        return new CompanyRecordSet(concat(people, other.people), distinct(concat(sources, other.sources)),
                concat(assignments, other.assignments), concat(approvals, other.approvals),
                concat(tickets, other.tickets), concat(onCall, other.onCall), concat(travel, other.travel),
                concat(accessDays, other.accessDays), concat(usage, other.usage), concat(policies, other.policies),
                concat(networks, other.networks));
    }

    public boolean isEmpty() {
        return size() == 0;
    }

    /** How many records the set holds; a named source counts as one. */
    public int size() {
        return people.size() + sources.size() + assignments.size() + approvals.size() + tickets.size()
                + onCall.size() + travel.size() + accessDays.size() + usage.size() + policies.size()
                + networks.size();
    }

    /**
     * The kinds the set integrates: those it names and those it holds records of. A person, usage, a rule and a
     * network are no kind a request is looked up in.
     */
    public Set<CompanyRecordKind> integratedKinds() {
        Set<CompanyRecordKind> kinds = new LinkedHashSet<>();
        for (String source : sources) {
            CompanyRecordKind kind = CompanyRecordKind.of(source);
            if (kind != null && kind.lookedUp()) {
                kinds.add(kind);
            }
        }
        addIf(kinds, !assignments.isEmpty(), CompanyRecordKind.ASSIGNMENT);
        addIf(kinds, !approvals.isEmpty(), CompanyRecordKind.APPROVAL);
        addIf(kinds, !tickets.isEmpty(), CompanyRecordKind.TICKET);
        addIf(kinds, !onCall.isEmpty(), CompanyRecordKind.ON_CALL);
        addIf(kinds, !travel.isEmpty(), CompanyRecordKind.TRAVEL);
        addIf(kinds, !accessDays.isEmpty(), CompanyRecordKind.ACCESS_HISTORY);
        return kinds;
    }

    /** What is wrong with the records, each as a sentence; empty when they can be kept. */
    public List<String> problems() {
        List<String> problems = new ArrayList<>();
        for (String source : sources) {
            CompanyRecordKind kind = CompanyRecordKind.of(source);
            if (kind == null || !kind.lookedUp()) {
                problems.add("source '" + source + "' is not a kind a request is looked up in");
            }
        }
        people.forEach(person -> require(problems, "person", person.subject(), "subject", person.subject()));
        for (Assignment assignment : assignments) {
            require(problems, "assignment", assignment.key(), "subject", assignment.subject());
            require(problems, "assignment", assignment.key(), "target", assignment.target());
            if (assignment.from() != null && assignment.until() != null && assignment.until().isBefore(assignment.from())) {
                problems.add("assignment " + assignment.key() + " ends before it starts");
            }
        }
        for (Approval approval : approvals) {
            require(problems, "approval", approval.id(), "id", approval.id());
            require(problems, "approval", approval.id(), "subject", approval.subject());
            period(problems, "approval", approval.id(), approval.validFrom(), approval.validUntil());
            if (approval.maxItems() != null && approval.maxItems() < 0) {
                problems.add("approval " + approval.id() + " has a negative item limit");
            }
        }
        for (Ticket ticket : tickets) {
            require(problems, "ticket", ticket.id(), "id", ticket.id());
            require(problems, "ticket", ticket.id(), "subject", ticket.subject());
            period(problems, "ticket", ticket.id(), ticket.validFrom(), ticket.validUntil());
        }
        for (OnCall shift : onCall) {
            require(problems, "on-call shift", shift.id(), "id", shift.id());
            require(problems, "on-call shift", shift.id(), "subject", shift.subject());
            period(problems, "on-call shift", shift.id(), shift.startsAt(), shift.endsAt());
        }
        for (Travel trip : travel) {
            require(problems, "trip", trip.id(), "id", trip.id());
            require(problems, "trip", trip.id(), "subject", trip.subject());
            period(problems, "trip", trip.id(), trip.validFrom(), trip.validUntil());
            if (trip.network() != null && !trip.network().isBlank() && !NetworkBlocks.valid(trip.network())) {
                problems.add("trip " + trip.id() + " has no valid network block");
            }
        }
        for (AccessDay day : accessDays) {
            require(problems, "work day", day.key(), "subject", day.subject());
            require(problems, "work day", day.key(), "target", day.target());
            if (day.day() == null) {
                problems.add("work day " + day.key() + " names no day");
            }
        }
        for (Usage used : usage) {
            require(problems, "usage", used.key(), "subject", used.subject());
            require(problems, "usage", used.key(), "target", used.target());
            if (used.at() == null) {
                problems.add("usage " + used.key() + " names no time");
            }
            if (used.items() < 0) {
                problems.add("usage " + used.key() + " has negative items");
            }
        }
        for (Policy policy : policies) {
            require(problems, "policy", policy.id(), "id", policy.id());
            for (String kind : policy.records()) {
                CompanyRecordKind named = CompanyRecordKind.of(kind);
                if (named == null || !named.lookedUp()) {
                    problems.add("policy " + policy.id() + " checks '" + kind + "', not a kind a request is looked up in");
                }
            }
            for (Policy.Rule rule : policy.exceptions()) {
                if (rule.kind() == null || rule.kind().isBlank()) {
                    problems.add("policy " + policy.id() + " has an exception without a kind");
                }
            }
            if (policy.historyDays() != null && policy.historyDays() <= 0) {
                problems.add("policy " + policy.id() + " has no positive history days");
            }
        }
        for (NetworkZone network : networks) {
            if (!NetworkBlocks.valid(network.cidr())) {
                problems.add("network '" + network.cidr() + "' is not a valid network block");
            }
            require(problems, "network", network.cidr(), "zone", network.zone());
        }
        return problems;
    }

    static String upper(@Nullable String value) {
        return value == null || value.isBlank() ? null : value.trim().toUpperCase(Locale.ROOT);
    }

    private static void require(List<String> problems, String what, @Nullable String key, String field,
                                @Nullable String value) {
        if (value == null || value.isBlank()) {
            problems.add(what + (key != null && !key.isBlank() ? " " + key : "") + " names no " + field);
        }
    }

    private static void period(List<String> problems, String what, @Nullable String key, @Nullable Instant from,
                               @Nullable Instant until) {
        if (from != null && until != null && !until.isAfter(from)) {
            problems.add(what + " " + key + " ends before it starts");
        }
    }

    private static void addIf(Set<CompanyRecordKind> kinds, boolean holds, CompanyRecordKind kind) {
        if (holds) {
            kinds.add(kind);
        }
    }

    private static String join(Object... parts) {
        StringBuilder key = new StringBuilder();
        for (Object part : parts) {
            if (!key.isEmpty()) {
                key.append('|');
            }
            key.append(part == null ? "" : part);
        }
        return key.toString();
    }

    private static <T> List<T> copy(@Nullable List<T> values) {
        return values == null ? List.of() : values.stream().filter(Objects::nonNull).toList();
    }

    private static <T> List<T> concat(List<T> first, List<T> second) {
        return Stream.concat(first.stream(), second.stream()).toList();
    }

    private static List<String> distinct(List<String> values) {
        return new ArrayList<>(new LinkedHashSet<>(values));
    }
}
