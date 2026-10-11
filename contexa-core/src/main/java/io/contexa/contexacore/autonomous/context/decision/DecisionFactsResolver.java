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

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AccessHistoryRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.ApprovalRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.AssignmentRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.CompanyPolicy;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.FrictionProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.OnCallRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PeerCohortProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.PolicyException;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.RoleScopeProfile;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.TicketRecord;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext.TravelRecord;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.learning.evidence.ObservedPatternSnapshot;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.DayOfWeek;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

/**
 * Computes the decision facts of a request (W2-5): how the request compares with the usual behaviour on each
 * dimension, how often each value was seen and whether a record explains a difference; the company's policy and
 * whether it is satisfied at the request time; the approval, assignment, ticket, on-call and trip records; the
 * request's repeats in the session; the scope group comparison, the data conflicts and the cohort comparison. A fact
 * the engine cannot establish is not given a line but named as unknown. The engine states facts, it does not decide:
 * the decision stays with the model and the minimum-action rules that read these facts.
 */
public final class DecisionFactsResolver {

    public static final String DEVIATIONS_FROM_BASELINE = "DeviationsFromBaseline";
    public static final String SAME_AS_BASELINE = "SameAsBaseline";
    public static final String POLICY = "Policy";
    public static final String POLICY_SATISFIED = "PolicySatisfied";
    public static final String APPROVAL = "Approval";
    public static final String ASSIGNMENT = "Assignment";
    public static final String TICKET = "Ticket";
    public static final String ON_CALL = "OnCall";
    public static final String TRAVEL = "Travel";
    public static final String REPEAT_IN_SESSION = "RepeatInSession";
    public static final String ROLE_SCOPE = "RoleScope";
    public static final String DATA_CONFLICTS = "DataConflicts";
    public static final String PEER_COHORT = "PeerCohort";

    private static final long HOUR_MS = 60L * 60L * 1_000L;
    private static final String EXPORT = "EXPORT";
    private static final String ALLOW = "ALLOW";

    private DecisionFactsResolver() {
    }

    public static DecisionFacts resolve(CanonicalSecurityContext context, LearningContextEvidence evidence,
                                        ZoneId zone) {
        if (context == null) {
            return DecisionFacts.NONE;
        }
        ZoneId clock = zone != null ? zone : ZoneId.systemDefault();
        List<SessionDecisionRecord> decisions = context.getSessionNarrativeProfile() != null
                && context.getSessionNarrativeProfile().getSessionDecisions() != null
                ? context.getSessionNarrativeProfile().getSessionDecisions() : List.of();
        CompanyRecordsEvaluator.Request request = CompanyRecordsEvaluator.Request.of(context, decisions);
        FrictionProfile friction = context.getFrictionProfile();
        CompanyRecordsEvaluator.Evaluation records = CompanyRecordsEvaluator.evaluate(friction, request, clock);
        List<Deviation> deviations = deviations(context, evidence, request, records, clock);

        Facts facts = new Facts();
        deviationFacts(facts, deviations, evidence);
        policyFacts(facts, friction, records);
        recordFacts(facts, context, friction, request, records, clock);
        String repeat = repeat(context, request);
        facts.add(REPEAT_IN_SESSION, repeat, repeat != null && !repeat.startsWith("first ")
                ? List.of("REPEAT_IN_SESSION") : List.of(), List.of(), DecisionFact.COMPUTED);
        roleScope(facts, context);
        dataConflicts(facts, context);
        peerCohort(facts, context);
        return new DecisionFacts(facts.known, deviations, records.policy(), facts.unknown);
    }

    // ---- comparison with the usual behaviour

    static List<Deviation> deviations(CanonicalSecurityContext context, LearningContextEvidence evidence,
                                      CompanyRecordsEvaluator.Request request,
                                      CompanyRecordsEvaluator.Evaluation records, ZoneId zone) {
        CurrentLearningContextSnapshot current = evidence != null ? evidence.current() : null;
        BaselineView view = evidence != null && evidence.baselineView() != null ? evidence.baselineView()
                : context.getWorkProfile() != null ? context.getWorkProfile().getBaselineView() : null;
        boolean windowObserved = view != null && view.observed();
        BaselineEvidenceSnapshot personal = evidence != null ? evidence.personalBaseline() : null;
        boolean personalLearned = personal != null && personal.available() && personal.hasAnyObservedFacts();
        Integer learned = personal != null && personal.updateCount() != null
                ? personal.updateCount().intValue() : null;
        Explainers explainers = explainers(context, records);
        LocalDateTime at = request.at() != null ? LocalDateTime.ofInstant(request.at(), zone) : null;

        List<Deviation> deviations = new ArrayList<>();
        Integer hour = at != null ? Integer.valueOf(at.getHour()) : integer(current != null ? current.accessHour() : null);
        deviations.add(windowObserved && hour != null
                ? compare(DeviationDimension.TIME, String.format(Locale.ROOT, "%02d", hour),
                !view.seenHours().contains(hour), count(view.counts().hours(), hour), view.observations(),
                explainers)
                : Deviation.notCompared(DeviationDimension.TIME, hour != null ? String.format(Locale.ROOT, "%02d", hour) : null));

        Integer day = at != null ? Integer.valueOf(at.getDayOfWeek().getValue()) : integer(current != null ? current.dayOfWeek() : null);
        String dayName = day != null && day >= 1 && day <= 7
                ? DayOfWeek.of(day).getDisplayName(TextStyle.SHORT, Locale.ROOT) : null;
        deviations.add(windowObserved && day != null
                ? compare(DeviationDimension.DAY, dayName, !view.seenDays().contains(day),
                count(view.counts().days(), day), view.counts().dayObservations(), explainers)
                : Deviation.notCompared(DeviationDimension.DAY, dayName));

        String network = current != null ? current.network() : null;
        deviations.add(personalLearned && network != null && !personal.networks().isEmpty()
                ? compare(DeviationDimension.NETWORK, network,
                personal.networks().stream().noneMatch(value -> network.equals(SecuritySemanticNormalizer.normalizeNetwork(null, value))),
                frequency(personal, "ip:", network, value -> SecuritySemanticNormalizer.normalizeNetwork(null, value)),
                learned, explainers)
                : Deviation.notCompared(DeviationDimension.NETWORK, network));

        String device = current != null ? current.device() : null;
        Boolean deviceHeld = personalLearned && current != null
                ? ObservedPatternSnapshot.holdsDevice(personal.devices(), personal.browsers(),
                personal.operatingSystems(), current.browser(), current.operatingSystem())
                : null;
        deviations.add(deviceHeld != null
                ? compare(DeviationDimension.DEVICE, device, !deviceHeld,
                personal.devices().isEmpty() ? null : frequency(personal, "device:", device, UnaryOperator.identity()),
                personal.devices().isEmpty() ? null : learned, explainers)
                : Deviation.notCompared(DeviationDimension.DEVICE, device));

        String login = current != null ? current.authenticationType() : null;
        deviations.add(personalLearned && login != null && !personal.authenticationTypes().isEmpty()
                ? compare(DeviationDimension.LOGIN_METHOD, login,
                personal.authenticationTypes().stream().noneMatch(value -> login.equalsIgnoreCase(
                        String.valueOf(SecuritySemanticNormalizer.normalizeAuthenticationType(value)))),
                frequency(personal, "auth:", login, SecuritySemanticNormalizer::normalizeAuthenticationType),
                learned, explainers)
                : Deviation.notCompared(DeviationDimension.LOGIN_METHOD, login));

        String target = request.target();
        // A target is compared only where the usual behaviour has usual targets of the same kind (projectKey=…):
        // documents and customers are each read once in the usual course, so a new one is no departure.
        deviations.add(windowObserved && target != null && hasUsualTargetOfKind(view, target)
                ? compare(DeviationDimension.TARGET, request.targetValues(),
                !view.counts().targets().containsKey(target), count(view.counts().targets(), target),
                view.observations(), explainers)
                : Deviation.notCompared(DeviationDimension.TARGET, request.targetValues()));

        String action = action(context, current);
        deviations.add(windowObserved && action != null && !view.actionCounts().isEmpty()
                ? compare(DeviationDimension.ACTION, action, !view.actionCounts().containsKey(action),
                count(view.actionCounts(), action), view.observations(), explainers)
                : Deviation.notCompared(DeviationDimension.ACTION, action));

        String resourceClass = current != null
                ? SecuritySemanticNormalizer.normalizeResourceFamily(current.resourceFamily()) : null;
        Map<String, Integer> classCounts = classCounts(view);
        deviations.add(windowObserved && resourceClass != null && !classCounts.isEmpty()
                ? compare(DeviationDimension.RESOURCE_CLASS, resourceClass, !classCounts.containsKey(resourceClass),
                count(classCounts, resourceClass), view.observations(), explainers)
                : Deviation.notCompared(DeviationDimension.RESOURCE_CLASS, resourceClass));

        Integer items = request.items();
        BaselineView.ExportSize exportSize = view != null ? view.exportSize() : null;
        String size = items != null ? CompanyRecordsEvaluator.number(items) + " items" : null;
        if (windowObserved && items != null && exportSize != null && exportSize.exports() > 0) {
            boolean different = items > exportSize.largestItems();
            deviations.add(new Deviation(DeviationDimension.SIZE, size, true, different, null, null,
                    "up to " + CompanyRecordsEvaluator.number(exportSize.largestItems()) + " items per export (median "
                            + CompanyRecordsEvaluator.number(exportSize.medianItems()) + ", "
                            + exportSize.exports() + " exports)",
                    different ? explain(DeviationDimension.SIZE, explainers) : null,
                    different ? explainers.by(DeviationDimension.SIZE) : null));
        }
        else {
            deviations.add(Deviation.notCompared(DeviationDimension.SIZE, size));
        }

        if (windowObserved && request.at() != null && view.counts().busiestActiveHourRequests() > 0) {
            int lastHour = 1 + (int) request.sessionDecisions().stream()
                    .filter(decision -> decision != null && decision.at() != null
                            && decision.at().isBefore(request.at())
                            && request.at().toEpochMilli() - decision.at().toEpochMilli() < HOUR_MS)
                    .count();
            int busiest = view.counts().busiestActiveHourRequests();
            boolean different = lastHour > busiest;
            deviations.add(new Deviation(DeviationDimension.RATE, lastHour + " requests in the last hour", true,
                    different, null, null, "at most " + busiest + " in one hour",
                    different ? explain(DeviationDimension.RATE, explainers) : null,
                    different ? explainers.by(DeviationDimension.RATE) : null));
        }
        else {
            deviations.add(Deviation.notCompared(DeviationDimension.RATE, null));
        }
        return deviations;
    }

    private static Deviation compare(DeviationDimension dimension, String current, boolean different, Integer seen,
                                     Integer of, Explainers explainers) {
        return new Deviation(dimension, current, true, different, seen, seen != null ? of : null, null,
                different ? explain(dimension, explainers) : null,
                different ? explainers.by(dimension) : null);
    }

    private static Deviation.Explanation explain(DeviationDimension dimension, Explainers explainers) {
        return explainers.by(dimension) != null ? Deviation.Explanation.EXPLAINED : Deviation.Explanation.UNEXPLAINED;
    }

    /** What may explain a difference: the record covering the work, and the trip holding the request address. */
    private record Explainers(String coveringRecord, String trip) {

        String by(DeviationDimension dimension) {
            return switch (dimension.explainer()) {
                case COVERING_RECORD -> coveringRecord;
                case TRAVEL -> trip;
                case NONE -> null;
            };
        }
    }

    private static Explainers explainers(CanonicalSecurityContext context, CompanyRecordsEvaluator.Evaluation records) {
        String covering = records.covering().map(RecordCheck::recordId).orElse(null);
        TravelRecord travel = context.getFrictionProfile() != null ? context.getFrictionProfile().getTravel() : null;
        String trip = travel != null && Boolean.TRUE.equals(tripHoldsAddress(travel, clientIp(context)))
                ? "trip " + (StringUtils.hasText(travel.getPlanId()) ? travel.getPlanId() : "registered by the host")
                : null;
        return new Explainers(covering, trip);
    }

    /**
     * Whether the registered trip's network holds the request address, IPv4 or IPv6. Null when the trip states no
     * network, the request has no address, or the two are not comparable: then it is not known, not held
     * (P2 correction 3).
     */
    static Boolean tripHoldsAddress(TravelRecord travel, String address) {
        if (travel == null) {
            return false;
        }
        if (!StringUtils.hasText(travel.getNetwork()) || !StringUtils.hasText(address)) {
            return null;
        }
        String[] parts = travel.getNetwork().trim().split("/");
        byte[] ip = literal(address.trim());
        byte[] base = literal(parts[0].trim());
        if (ip == null || base == null || ip.length != base.length || parts.length > 2) {
            return null;
        }
        int bits = ip.length * 8;
        int length = bits;
        if (parts.length == 2) {
            try {
                length = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (length < 0 || length > bits) {
            return null;
        }
        for (int bit = 0; bit < length; bit++) {
            int mask = 0x80 >> (bit % 8);
            if ((ip[bit / 8] & mask) != (base[bit / 8] & mask)) {
                return false;
            }
        }
        return true;
    }

    /** The bytes of an IPv4 or IPv6 address literal, null for anything else; no name is resolved. */
    private static byte[] literal(String address) {
        if (address.contains(":")) {
            if (!address.matches("[0-9A-Fa-f:.]+")) {
                return null;
            }
            try {
                return InetAddress.getByName(address).getAddress();
            } catch (UnknownHostException e) {
                return null;
            }
        }
        Long value = ipv4(address);
        if (value == null) {
            return null;
        }
        return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) (value & 0xFF)};
    }

    private static Long ipv4(String address) {
        String[] octets = address.trim().split("\\.");
        if (octets.length != 4) {
            return null;
        }
        long value = 0;
        for (String octet : octets) {
            try {
                int part = Integer.parseInt(octet);
                if (part < 0 || part > 255) {
                    return null;
                }
                value = (value << 8) | part;
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return value;
    }

    private static void deviationFacts(Facts facts, List<Deviation> deviations, LearningContextEvidence evidence) {
        List<Deviation> compared = deviations.stream().filter(Deviation::compared).toList();
        if (compared.isEmpty()) {
            facts.unknown(DEVIATIONS_FROM_BASELINE);
            facts.unknown(SAME_AS_BASELINE);
            return;
        }
        List<Deviation> different = compared.stream().filter(Deviation::different).toList();
        StringBuilder value = new StringBuilder()
                .append(different.size()).append(" of ").append(compared.size()).append(" compared");
        if (!different.isEmpty()) {
            value.append(" -> ").append(different.stream().map(Deviation::describe).collect(Collectors.joining("; ")));
        }
        // The past records are searched within the request's resource, so their action, resource class and path
        // family match by construction; the closest one is compared on what the search leaves free (P2 correction 3).
        String overlap = evidence != null ? evidence.currentRequestClosestOverlapOutsideRetrievalScope() : null;
        if (overlap != null && overlap.contains("/")) {
            value.append("; closest past record of this resource matches ").append(overlap.replace("/", " of "))
                    .append(" on time, login method and browser");
        }
        List<String> explaining = different.stream().map(Deviation::explainedBy).filter(StringUtils::hasText)
                .distinct().toList();
        facts.add(DEVIATIONS_FROM_BASELINE, value.toString(),
                different.stream().map(deviation -> deviation.dimension().code()).toList(), explaining,
                DecisionFact.COMPUTED);
        List<Deviation> same = compared.stream().filter(deviation -> !deviation.different()).toList();
        facts.add(SAME_AS_BASELINE, same.isEmpty() ? "none"
                        : same.stream().map(deviation -> deviation.dimension().label()).collect(Collectors.joining(", ")),
                same.isEmpty() ? List.of() : List.of("BASELINE_MATCH"), List.of(), DecisionFact.COMPUTED);
    }

    // ---- company policy and records

    private static void policyFacts(Facts facts, FrictionProfile friction,
                                    CompanyRecordsEvaluator.Evaluation records) {
        List<CompanyPolicy> policies = friction != null && friction.getPolicies() != null
                ? friction.getPolicies().stream().filter(policy -> policy != null).toList() : List.of();
        facts.add(POLICY, policies.isEmpty() ? null
                : policies.stream().map(DecisionFactsResolver::describePolicy).collect(Collectors.joining("; ")),
                DecisionFact.HOST);
        PolicySatisfaction satisfaction = records.policy();
        String value = satisfaction.describe();
        List<String> codes = satisfaction.satisfied() == null ? List.of()
                : satisfaction.satisfied() ? List.of("POLICY_SATISFIED") : List.of(satisfaction.reason().code());
        facts.add(POLICY_SATISFIED, value, codes, satisfaction.recordIds(), DecisionFact.COMPUTED);
    }

    static String describePolicy(CompanyPolicy policy) {
        String requirement = policy.getRequirement() == null ? "" : policy.getRequirement().trim().toUpperCase(Locale.ROOT);
        String kind = StringUtils.hasText(policy.getRequiredTicketKind())
                ? policy.getRequiredTicketKind().trim().toUpperCase(Locale.ROOT) + " " : "";
        String needs = switch (requirement) {
            case "APPROVAL" -> "a covering approval";
            case "TICKET" -> "a covering " + kind + "ticket";
            default -> "a covering record (" + (requirement.isEmpty() ? "not stated" : requirement) + ")";
        };
        List<String> exceptions = new ArrayList<>();
        if (policy.getExceptions() != null) {
            for (PolicyException exception : policy.getExceptions()) {
                if (exception == null || !StringUtils.hasText(exception.getKind())) {
                    continue;
                }
                exceptions.add(switch (exception.getKind().trim().toUpperCase(Locale.ROOT)) {
                    case "ASSIGNED" -> exception.getLimit() != null
                            ? "assigned target up to " + CompanyRecordsEvaluator.number(exception.getLimit()) + " items"
                            : "assigned target";
                    case "ACCOUNT_MANAGER" -> "account manager";
                    case "RECENT_WORK" -> "worked on the target in the last "
                            + (exception.getLimit() != null ? exception.getLimit() + " days" : "days the host sets");
                    case "TICKET_WHILE_ON_CALL" -> "ticket while on call";
                    default -> exception.getKind().trim().toLowerCase(Locale.ROOT).replace('_', ' ');
                });
            }
        }
        return (StringUtils.hasText(policy.getPolicyId()) ? policy.getPolicyId() : "company policy") + " requires "
                + needs + (exceptions.isEmpty() ? "" : " (exceptions: " + String.join("; ", exceptions) + ")");
    }

    private static void recordFacts(Facts facts, CanonicalSecurityContext context, FrictionProfile friction,
                                    CompanyRecordsEvaluator.Request request,
                                    CompanyRecordsEvaluator.Evaluation records, ZoneId zone) {
        // An approval line is conditional: it is there when the host stated an approval record.
        if (!records.approvals().isEmpty()) {
            List<String> lines = new ArrayList<>();
            for (RecordCheck check : records.approvals()) {
                ApprovalRecord record = friction.getApprovalRecords().stream()
                        .filter(approval -> approval != null && check.recordId().equals(approval.getApprovalId()))
                        .findFirst().orElse(null);
                lines.add(describeApproval(record, check, zone));
            }
            facts.add(APPROVAL, String.join("; ", lines),
                    records.approvals().stream().anyMatch(RecordCheck::valid) ? List.of("APPROVAL_COVERS") : List.of(),
                    records.approvals().stream().map(RecordCheck::recordId).toList(), DecisionFact.HOST);
        }

        facts.add(ASSIGNMENT, assignment(friction, request), friction != null && friction.getAssignment() != null
                        && Boolean.TRUE.equals(friction.getAssignment().getAssigned()) ? List.of("ASSIGNED_TARGET") : List.of(),
                List.of(), DecisionFact.HOST);

        if (!records.tickets().isEmpty()) {
            List<String> lines = new ArrayList<>();
            List<String> codes = new ArrayList<>();
            for (RecordCheck check : records.tickets()) {
                TicketRecord record = friction.getTicketRecords().stream()
                        .filter(ticket -> ticket != null && check.recordId().equals(ticket.getTicketId()))
                        .findFirst().orElse(null);
                lines.add(describeTicket(record, check, zone));
                if (check.valid() && !codes.contains("TICKET_COVERS")) {
                    codes.add("TICKET_COVERS");
                }
                if (check.claimFalse() && !codes.contains("TICKET_CLAIM_FALSE")) {
                    codes.add("TICKET_CLAIM_FALSE");
                }
            }
            facts.add(TICKET, String.join("; ", lines), codes,
                    records.tickets().stream().map(RecordCheck::recordId).distinct().toList(), DecisionFact.HOST);
        }
        else {
            // A ticket the host did not look up is not known, not absent (P2 correction 3).
            facts.add(TICKET, CompanyRecordsEvaluator.checked(friction, FrictionProfile.RECORD_TICKET)
                    ? "no ticket found" : null, DecisionFact.HOST);
        }

        OnCallRecord onCall = friction != null ? friction.getOnCall() : null;
        Boolean onCallNow = records.onCall();
        facts.add(ON_CALL, onCallNow == null ? null : onCallNow
                        ? "on call" + (StringUtils.hasText(onCall.getTeam()) ? " (" + onCall.getTeam() + ")" : "")
                        + (onCall.getEndsAt() != null ? " until " + CompanyRecordsEvaluator.wallClock(onCall.getEndsAt(), zone) : "")
                        : "not on call",
                Boolean.TRUE.equals(onCallNow) ? List.of("ON_CALL") : List.of(), List.of(), DecisionFact.HOST);

        TravelRecord travel = friction != null ? friction.getTravel() : null;
        if (travel != null) {
            Boolean holds = tripHoldsAddress(travel, clientIp(context));
            facts.add(TRAVEL, "trip " + (StringUtils.hasText(travel.getPlanId()) ? travel.getPlanId() + " " : "")
                            + "to " + joinText(" ", travel.getCity(), travel.getCountry())
                            + (StringUtils.hasText(travel.getNetwork()) ? ", network " + travel.getNetwork() : "")
                            + (holds == null ? ", whether it holds the request address is not known"
                            : holds ? " holds the request address" : " does not hold the request address"),
                    Boolean.TRUE.equals(holds) ? List.of("TRAVEL_EXPLAINS_NETWORK") : List.of(),
                    StringUtils.hasText(travel.getPlanId()) ? List.of(travel.getPlanId()) : List.of(), DecisionFact.HOST);
        }
        else {
            // Only a host that looked up trips can say none holds the address (P2 correction 3).
            facts.add(TRAVEL, CompanyRecordsEvaluator.checked(friction, FrictionProfile.RECORD_TRAVEL)
                    ? "no registered trip holds the request address" : null, DecisionFact.HOST);
        }
    }

    static String describeApproval(ApprovalRecord record, RecordCheck check, ZoneId zone) {
        StringBuilder text = new StringBuilder(check.recordId());
        if (record != null) {
            if (StringUtils.hasText(record.getApprover())) {
                text.append(" by ").append(record.getApprover());
            }
            appendPart(text, record.getStatus());
            appendPart(text, record.getPurpose());
            appendPart(text, record.getTarget());
            if (record.getMaxItems() != null) {
                appendPart(text, "up to " + CompanyRecordsEvaluator.number(record.getMaxItems()) + " items");
            }
            if (check.usedBefore() != null) {
                appendPart(text, "used " + CompanyRecordsEvaluator.number(check.usedBefore()) + " before this request");
            }
            if (record.getValidFrom() != null || record.getValidUntil() != null) {
                appendPart(text, "valid " + CompanyRecordsEvaluator.window(record.getValidFrom(), record.getValidUntil(), zone));
            }
            appendPart(text, record.getDecidedAt() != null
                    ? "decided " + CompanyRecordsEvaluator.wallClock(record.getDecidedAt(), zone)
                    : "decision time not recorded");
            if (record.getPendingApprovers() != null && !record.getPendingApprovers().isEmpty()) {
                appendPart(text, "pending " + String.join(", ", record.getPendingApprovers()));
            }
            if (Boolean.TRUE.equals(record.getBreakGlass())) {
                appendPart(text, "break-glass");
            }
        }
        text.append(check.valid() ? " — covers this request"
                : check.undecided() ? " — not known whether it covers: " + String.join("; ", check.unknowns())
                : " — does not cover: " + String.join("; ", check.notes()));
        return text.toString();
    }

    static String describeTicket(TicketRecord record, RecordCheck check, ZoneId zone) {
        if (check.claimFalse()) {
            return check.recordId() + " named by the requester does not exist";
        }
        StringBuilder text = new StringBuilder(check.recordId());
        if (record != null) {
            if (StringUtils.hasText(record.getKind())) {
                text.append(' ').append(record.getKind().trim().toUpperCase(Locale.ROOT));
            }
            if (StringUtils.hasText(record.getApprover())) {
                text.append(" by ").append(record.getApprover());
            }
            appendPart(text, record.getStatus());
            appendPart(text, record.getPurpose());
            appendPart(text, record.getTarget());
            if (record.getValidFrom() != null || record.getValidUntil() != null) {
                appendPart(text, "valid " + CompanyRecordsEvaluator.window(record.getValidFrom(), record.getValidUntil(), zone));
            }
            if (Boolean.TRUE.equals(record.getClaimedByRequester())) {
                appendPart(text, "named by the requester");
            }
        }
        text.append(check.valid() ? " — covers this request" : " — does not cover: " + String.join("; ", check.notes()));
        return text.toString();
    }

    private static String assignment(FrictionProfile friction, CompanyRecordsEvaluator.Request request) {
        if (friction == null || (friction.getAssignment() == null && friction.getAccessHistory() == null)) {
            return null;
        }
        String target = CompanyRecordsEvaluator.targetName(friction, request);
        List<String> parts = new ArrayList<>();
        AssignmentRecord assignment = friction.getAssignment();
        if (assignment != null && assignment.getAssigned() != null) {
            String responsibility = assignment.getResponsibility();
            if (CompanyRecordsEvaluator.ACCOUNT_MANAGER.equalsIgnoreCase(String.valueOf(responsibility))) {
                parts.add((assignment.getAssigned() ? "account manager of " : "not the account manager of ") + target);
            }
            else {
                parts.add((assignment.getAssigned() ? "assigned to " : "not assigned to ") + target
                        + (assignment.getAssigned() && StringUtils.hasText(responsibility)
                        ? " (" + responsibility + ")" : ""));
            }
        }
        AccessHistoryRecord history = friction.getAccessHistory();
        if (history != null && history.getDays() != null) {
            parts.add("worked on " + target + " on " + history.getDays() + " of the last "
                    + (history.getWindowDays() != null ? history.getWindowDays() + " days" : "days the host counts"));
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    // ---- the session, the scope group, conflicts and the cohort

    private static String repeat(CanonicalSecurityContext context, CompanyRecordsEvaluator.Request request) {
        if (context.getSessionNarrativeProfile() == null) {
            return null;
        }
        String action = action(context, null);
        String what = action != null ? action : "request";
        // The same action is repeated whatever its target (six downloads of six drawings); what was done to the same
        // target, and the items exported to it, are said apart.
        List<SessionDecisionRecord> sameAction = request.sessionDecisions().stream()
                .filter(decision -> decision != null && action != null && action.equals(decision.actionFamily()))
                .toList();
        if (sameAction.isEmpty()) {
            return "first " + what + (request.targetValues() != null ? " of " + request.targetValues() : "")
                    + " in this session";
        }
        StringBuilder text = new StringBuilder(ordinal(sameAction.size() + 1)).append(' ').append(what)
                .append(" in this session");
        if (request.target() != null) {
            List<SessionDecisionRecord> sameTarget = sameAction.stream()
                    .filter(decision -> request.target().equals(decision.target())).toList();
            if (!sameTarget.isEmpty()) {
                text.append(", ").append(sameTarget.size()).append(" earlier of ").append(request.targetValues());
                int exported = sameTarget.stream()
                        .filter(decision -> decision.items() != null
                                && ALLOW.equalsIgnoreCase(String.valueOf(decision.outcome())))
                        .mapToInt(SessionDecisionRecord::items).sum();
                if (exported > 0) {
                    text.append("; ").append(CompanyRecordsEvaluator.number(exported)).append(" items exported to ")
                            .append(request.targetValues()).append(" before this request");
                }
            }
        }
        return text.toString();
    }

    private static void roleScope(Facts facts, CanonicalSecurityContext context) {
        RoleScopeProfile scope = context.getRoleScopeProfile();
        if (scope == null || (scope.getExpectedActionFamilies().isEmpty() && scope.getExpectedResourceFamilies().isEmpty()
                && scope.getActionFamilyDrift() == null && scope.getResourceFamilyDrift() == null)) {
            facts.unknown(ROLE_SCOPE);
            return;
        }
        List<String> parts = new ArrayList<>();
        String action = StringUtils.hasText(scope.getCurrentActionFamily()) ? scope.getCurrentActionFamily()
                : action(context, null);
        if (action != null && !scope.getExpectedActionFamilies().isEmpty()) {
            parts.add("action " + action + (Boolean.TRUE.equals(scope.getActionFamilyDrift()) ? " outside" : " within")
                    + " the scope group's actions (" + String.join(", ", scope.getExpectedActionFamilies()) + ")");
        }
        if (StringUtils.hasText(scope.getCurrentResourceFamily()) && !scope.getExpectedResourceFamilies().isEmpty()) {
            parts.add("class " + scope.getCurrentResourceFamily()
                    + (Boolean.TRUE.equals(scope.getResourceFamilyDrift()) ? " outside" : " within")
                    + " the scope group's classes (" + String.join(", ", scope.getExpectedResourceFamilies()) + ")");
        }
        if (Boolean.TRUE.equals(scope.getCurrentActionFamilyInDeniedScope())) {
            parts.add("action in the scope group's denied actions");
        }
        if (Boolean.TRUE.equals(scope.getCurrentResourceFamilyInDeniedScope())) {
            parts.add("class in the scope group's denied classes");
        }
        boolean outside = Boolean.TRUE.equals(scope.getActionFamilyDrift())
                || Boolean.TRUE.equals(scope.getResourceFamilyDrift())
                || Boolean.TRUE.equals(scope.getCurrentActionFamilyInDeniedScope())
                || Boolean.TRUE.equals(scope.getCurrentResourceFamilyInDeniedScope());
        if (parts.isEmpty()) {
            facts.unknown(ROLE_SCOPE);
            return;
        }
        facts.add(ROLE_SCOPE, String.join("; ", parts), outside ? List.of("ROLE_SCOPE_OUTSIDE") : List.of(),
                List.of(), DecisionFact.LEARNED);
    }

    private static void dataConflicts(Facts facts, CanonicalSecurityContext context) {
        List<CanonicalSecurityContext.DataConflict> conflicts = context.getDataConflicts() == null ? List.of()
                : context.getDataConflicts().stream().filter(conflict -> conflict != null
                && StringUtils.hasText(conflict.getField())).toList();
        if (conflicts.isEmpty()) {
            return;
        }
        List<String> codes = new ArrayList<>();
        List<String> parts = new ArrayList<>();
        for (CanonicalSecurityContext.DataConflict conflict : conflicts) {
            String field = conflict.getField();
            String lower = field.toLowerCase(Locale.ROOT);
            String code = lower.contains("tenant") || lower.contains("organization") ? "TENANT_CONFLICT"
                    : lower.contains("authoriz") ? "AUTHORIZATION_CONFLICT" : "DATA_CONFLICT";
            if (!codes.contains(code)) {
                codes.add(code);
            }
            String sources = conflict.getSources() == null ? "" : conflict.getSources().entrySet().stream()
                    .map(entry -> entry.getKey() + " " + entry.getValue()).collect(Collectors.joining(", "));
            parts.add(field + (sources.isEmpty() ? "" : " (" + sources + ")"));
        }
        facts.add(DATA_CONFLICTS, String.join("; ", parts), codes, List.of(), DecisionFact.COMPUTED);
    }

    private static void peerCohort(Facts facts, CanonicalSecurityContext context) {
        PeerCohortProfile cohort = context.getPeerCohortProfile();
        if (cohort == null || (cohort.getPreferredActionFamilies().isEmpty() && cohort.getPreferredResources().isEmpty()
                && cohort.getOutlierAgainstCohort() == null)) {
            facts.unknown(PEER_COHORT);
            return;
        }
        List<String> parts = new ArrayList<>();
        String action = action(context, null);
        if (action != null && !cohort.getPreferredActionFamilies().isEmpty()) {
            boolean usual = cohort.getPreferredActionFamilies().stream().anyMatch(action::equalsIgnoreCase);
            parts.add("action " + action + (usual ? " within" : " outside") + " the cohort's usual actions");
        }
        String resource = context.getResource() != null ? context.getResource().getResourceId() : null;
        if (resource != null && !cohort.getPreferredResources().isEmpty()) {
            boolean usual = cohort.getPreferredResources().stream().anyMatch(resource::equalsIgnoreCase);
            parts.add("resource " + (usual ? "within" : "outside") + " the cohort's usual resources");
        }
        if (cohort.getOutlierAgainstCohort() != null) {
            parts.add(cohort.getOutlierAgainstCohort() ? "an outlier against the cohort" : "not an outlier against the cohort");
        }
        facts.add(PEER_COHORT, (StringUtils.hasText(cohort.getCohortId()) ? "cohort " + cohort.getCohortId() + ": " : "")
                + String.join("; ", parts), List.of(), List.of(), DecisionFact.LEARNED);
    }

    // ---- helpers

    private static String action(CanonicalSecurityContext context, CurrentLearningContextSnapshot current) {
        if (current != null && StringUtils.hasText(current.actionFamily())) {
            return current.actionFamily();
        }
        if (context.getResource() != null && StringUtils.hasText(context.getResource().getActionFamily())) {
            return SecuritySemanticNormalizer.normalizeActionFamily(context.getResource().getActionFamily());
        }
        return null;
    }

    private static String clientIp(CanonicalSecurityContext context) {
        return context.getSession() != null ? context.getSession().getClientIp() : null;
    }

    /** Whether the view's usual targets hold one bound to the same template variables as the target. */
    static boolean hasUsualTargetOfKind(BaselineView view, String target) {
        String kind = variables(target);
        return view.usualTargets().stream().anyMatch(usual -> kind.equals(variables(usual)));
    }

    private static String variables(String binding) {
        StringBuilder names = new StringBuilder();
        for (String part : binding.split(",")) {
            int split = part.indexOf('=');
            names.append(split > 0 ? part.substring(0, split) : part).append(',');
        }
        return names.toString();
    }

    private static Map<String, Integer> classCounts(BaselineView view) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        if (view == null) {
            return counts;
        }
        for (String entry : view.resourceClasses()) {
            int split = entry.lastIndexOf('=');
            if (split <= 0) {
                continue;
            }
            Integer value = integer(entry.substring(split + 1));
            String name = SecuritySemanticNormalizer.normalizeResourceFamily(entry.substring(0, split));
            if (name != null && value != null) {
                counts.merge(name, value, Integer::sum);
            }
        }
        return counts;
    }

    private static <K> Integer count(Map<K, Integer> counts, K key) {
        if (counts == null || counts.isEmpty()) {
            return null;
        }
        return counts.getOrDefault(key, 0);
    }

    /** How many learned requests held the value, by the baseline's key prefix; null when the baseline keeps no count. */
    private static Integer frequency(BaselineEvidenceSnapshot baseline, String prefix, String value,
                                     UnaryOperator<String> normalizer) {
        if (baseline == null || value == null || baseline.elementFrequencies().isEmpty()) {
            return null;
        }
        boolean counted = false;
        long total = 0;
        for (Map.Entry<String, Long> entry : baseline.elementFrequencies().entrySet()) {
            if (!entry.getKey().startsWith(prefix)) {
                continue;
            }
            counted = true;
            String key = normalizer.apply(entry.getKey().substring(prefix.length()));
            if (key != null && key.equalsIgnoreCase(value)) {
                total += entry.getValue();
            }
        }
        return counted ? (int) total : null;
    }

    private static Integer integer(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            return Integer.valueOf(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String ordinal(int value) {
        int lastTwo = value % 100;
        String suffix = lastTwo >= 11 && lastTwo <= 13 ? "th" : switch (value % 10) {
            case 1 -> "st";
            case 2 -> "nd";
            case 3 -> "rd";
            default -> "th";
        };
        return value + suffix;
    }

    private static void appendPart(StringBuilder text, String part) {
        if (StringUtils.hasText(part)) {
            text.append(", ").append(part.trim());
        }
    }

    private static String joinText(String separator, String... parts) {
        List<String> present = new ArrayList<>();
        for (String part : parts) {
            if (StringUtils.hasText(part)) {
                present.add(part.trim());
            }
        }
        return present.isEmpty() ? "an unnamed place" : String.join(separator, present);
    }

    /** The facts in order: a known fact gets the next ID, an unknown one is only named. */
    private static final class Facts {

        private final List<DecisionFact> known = new ArrayList<>();
        private final List<String> unknown = new ArrayList<>();

        void add(String name, String value, String source) {
            add(name, value, List.of(), List.of(), source);
        }

        void add(String name, String value, List<String> codes, List<String> recordIds, String source) {
            if (!StringUtils.hasText(value)) {
                unknown(name);
                return;
            }
            known.add(new DecisionFact("F" + (known.size() + 1), name, value, codes, recordIds, source));
        }

        void unknown(String name) {
            if (!unknown.contains(name)) {
                unknown.add(name);
            }
        }
    }
}
