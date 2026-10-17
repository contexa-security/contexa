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
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
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
import io.contexa.contexacore.autonomous.context.policy.CanonicalContextFieldPolicy;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.learning.evidence.ObservedPatternSnapshot;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.DayOfWeek;
import java.time.Instant;
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
    public static final String MOVEMENT = "Movement";
    public static final String SESSION_DEVICE_CHANGE = "SessionDeviceChange";
    public static final String SESSION_NETWORK_CHANGE = "SessionNetworkChange";

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
        deviationFacts(facts, deviations, evidence, request.at(), clock);
        policyFacts(facts, friction, records);
        recordFacts(facts, context, friction, request, records, clock);
        String repeat = repeat(context, request);
        facts.add(REPEAT_IN_SESSION, repeat, repeat != null && !repeat.startsWith("first ")
                ? List.of("REPEAT_IN_SESSION") : List.of(), List.of(), DecisionFact.COMPUTED);
        roleScope(facts, context);
        dataConflicts(facts, context);
        peerCohort(facts, context);
        movement(facts, context);
        sessionClientChanges(facts, context);
        return new DecisionFacts(facts.known, deviations, records.policy(), facts.unknown, facts.unavailable);
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
        Explainers explainers = explainers(context, records, personal);
        LocalDateTime at = request.at() != null ? LocalDateTime.ofInstant(request.at(), zone) : null;

        List<Deviation> deviations = new ArrayList<>();
        Integer hour = at != null ? Integer.valueOf(at.getHour()) : integer(current != null ? current.accessHour() : null);
        String hourText = hour != null ? String.format(Locale.ROOT, "%02d", hour) : null;
        deviations.add(windowObserved && hour != null
                ? compare(DeviationDimension.TIME, hourText,
                !view.seenHours().contains(hour), count(view.counts().hours(), hour), view.observations(),
                explainers, seenOf(view, "TIME", hourText))
                : Deviation.notCompared(DeviationDimension.TIME, hourText, notComparedReason(windowObserved, hour, true)));

        Integer day = at != null ? Integer.valueOf(at.getDayOfWeek().getValue()) : integer(current != null ? current.dayOfWeek() : null);
        String dayName = day != null && day >= 1 && day <= 7
                ? DayOfWeek.of(day).getDisplayName(TextStyle.SHORT, Locale.ROOT) : null;
        deviations.add(windowObserved && day != null
                ? compare(DeviationDimension.DAY, dayName, !view.seenDays().contains(day),
                count(view.counts().days(), day), view.counts().dayObservations(), explainers,
                seenOf(view, "DAY", dayName))
                : Deviation.notCompared(DeviationDimension.DAY, dayName, notComparedReason(windowObserved, day, true)));

        // W5-9 (deep investigation R2): the network, device and login are compared with the view, as the time and the
        // target are, so the activity period being judged is left out of all of them by one rule; they are read
        // against the window's observations that hold them.
        BaselineView.Counts counts = view != null ? view.counts() : BaselineView.Counts.NONE;
        int identityObservations = counts.identityObservations();
        String network = current != null ? current.network() : null;
        deviations.add(windowObserved && network != null && !counts.networks().isEmpty()
                ? compare(DeviationDimension.NETWORK, network, !counts.networks().containsKey(network),
                count(counts.networks(), network), identityObservations, explainers, seenOf(view, "NETWORK", network))
                : Deviation.notCompared(DeviationDimension.NETWORK, network,
                notComparedReason(windowObserved, network, !counts.networks().isEmpty())));

        String device = current != null ? current.device() : null;
        Boolean deviceHeld = windowObserved && current != null && !counts.devices().isEmpty()
                ? ObservedPatternSnapshot.holdsDevice(view.usualDevices(), view.usualBrowsers(),
                view.usualOperatingSystems(), current.browser(), current.operatingSystem())
                : null;
        deviations.add(deviceHeld != null
                ? compare(DeviationDimension.DEVICE, device, !deviceHeld, count(counts.devices(), device),
                identityObservations, explainers, seenOf(view, "DEVICE", device))
                : Deviation.notCompared(DeviationDimension.DEVICE, device,
                notComparedReason(windowObserved, device, !counts.devices().isEmpty())));

        String login = current != null ? current.authenticationType() : null;
        // W5-10 D6 (P5-변경-17): a login that holds every method of a usual login, as PASSWORD with a one-time code
        // against the usual PASSWORD, is no departure; it is stated with the usual login it holds and that login's
        // count. A login missing a method of every usual login stays a difference.
        String usualHeld = login != null ? usualLoginHeld(login, counts.logins()) : null;
        boolean stronger = usualHeld != null && !usualHeld.equals(login);
        Deviation loginDeviation = windowObserved && login != null && !counts.logins().isEmpty()
                ? compare(DeviationDimension.LOGIN_METHOD, login, usualHeld == null,
                count(counts.logins(), stronger ? usualHeld : login), identityObservations, explainers,
                stronger ? null : seenOf(view, "LOGIN_METHOD", login))
                : Deviation.notCompared(DeviationDimension.LOGIN_METHOD, login,
                notComparedReason(windowObserved, login, !counts.logins().isEmpty()));
        if (stronger && loginDeviation.compared()) {
            // The usual login it holds is its usual value; the count is that login's.
            loginDeviation = new Deviation(loginDeviation.dimension(), loginDeviation.current(), true, false,
                    loginDeviation.seen(), loginDeviation.of(), usualHeld, loginDeviation.explanation(),
                    loginDeviation.explainedBy(), loginDeviation.observed(), loginDeviation.notComparedReason());
        }
        deviations.add(loginDeviation);

        String target = request.target();
        // The prompt names the target's variables; their values are the requester's text (N-INJ-1).
        String targetNames = target != null && context.getResource() != null
                ? BaselineViewCalculator.variables(context.getResource().getPathFamily()) : null;
        // A target is compared only where the usual behaviour has usual targets of the same kind (projectKey=…):
        // documents and customers are each read once in the usual course, so a new one is no departure.
        deviations.add(windowObserved && target != null && hasUsualTargetOfKind(view, target)
                ? compare(DeviationDimension.TARGET, targetNames,
                !view.counts().targets().containsKey(target), count(view.counts().targets(), target),
                view.observations(), explainers, seenOf(view, "TARGET", target))
                : Deviation.notCompared(DeviationDimension.TARGET, targetNames,
                windowObserved && target != null ? "no usual target of this kind"
                        : notComparedReason(windowObserved, target, true)));

        String action = action(context, current);
        deviations.add(windowObserved && action != null && !view.actionCounts().isEmpty()
                ? compare(DeviationDimension.ACTION, action, !view.actionCounts().containsKey(action),
                count(view.actionCounts(), action), view.observations(), explainers, seenOf(view, "ACTION", action))
                : Deviation.notCompared(DeviationDimension.ACTION, action,
                notComparedReason(windowObserved, action, view != null && !view.actionCounts().isEmpty())));

        String resourceClass = current != null
                ? SecuritySemanticNormalizer.normalizeResourceClass(current.resourceFamily()) : null;
        Map<String, Integer> classCounts = classCounts(view);
        deviations.add(windowObserved && resourceClass != null && !classCounts.isEmpty()
                ? compare(DeviationDimension.RESOURCE_CLASS, resourceClass, !classCounts.containsKey(resourceClass),
                count(classCounts, resourceClass), view.observations(), explainers,
                seenOf(view, "RESOURCE_CLASS", resourceClass))
                : Deviation.notCompared(DeviationDimension.RESOURCE_CLASS, resourceClass,
                notComparedReason(windowObserved, resourceClass, !classCounts.isEmpty())));

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
            deviations.add(Deviation.notCompared(DeviationDimension.SIZE, size,
                    windowObserved && items != null ? "no export in the window"
                            : notComparedReason(windowObserved, items, true)));
        }

        BaselineView.Rate rate = view != null && view.counts() != null ? view.counts().rate() : null;
        if (windowObserved && request.at() != null && rate != null) {
            // W5-10 D5, N-RATE-1: one definition of the rate: the user's requests in the last 60 minutes of the event
            // clock, this one included, against the same count taken at each request of the window; different above
            // its 95th percentile. Without the user's session list the count is the session's and says so.
            Integer userLastHour = context.getSessionNarrativeProfile() != null
                    ? context.getSessionNarrativeProfile().getUserRequestsLastHour() : null;
            int sessionLastHour = 1 + (int) request.sessionDecisions().stream()
                    .filter(decision -> decision != null && decision.at() != null
                            && decision.at().isBefore(request.at())
                            && request.at().toEpochMilli() - decision.at().toEpochMilli() < HOUR_MS)
                    .count();
            int lastHour = userLastHour != null ? userLastHour : sessionLastHour;
            boolean different = lastHour > rate.p95();
            deviations.add(new Deviation(DeviationDimension.RATE, lastHour + " requests in the last 60 min"
                    + (userLastHour != null ? "" : " of this session"), true, different, null, null,
                    "median " + rate.median() + ", 95th percentile " + rate.p95() + " " + BaselineView.Rate.WINDOW,
                    different ? explain(DeviationDimension.RATE, explainers) : null,
                    different ? explainers.by(DeviationDimension.RATE) : null));
        }
        else {
            deviations.add(Deviation.notCompared(DeviationDimension.RATE, null,
                    !windowObserved ? "no observations in the window"
                            : request.at() == null ? "the request time is not known" : "no usual rate in the view"));
        }
        return deviations;
    }

    private static Deviation compare(DeviationDimension dimension, String current, boolean different, Integer seen,
                                     Integer of, Explainers explainers) {
        return compare(dimension, current, different, seen, of, explainers, null);
    }

    /**
     * The comparison with how the request's value was seen (W5-10 D1~D3): when the view counted it, its count is read
     * against the observations that hold the dimension (D2).
     */
    private static Deviation compare(DeviationDimension dimension, String current, boolean different, Integer seen,
                                     Integer of, Explainers explainers, BaselineView.Seen observed) {
        Integer held = observed != null ? Integer.valueOf(observed.seen()) : seen;
        Integer among = observed != null ? Integer.valueOf(observed.of()) : of;
        return new Deviation(dimension, current, true, different, held, held != null ? among : null, null,
                different ? explain(dimension, explainers) : null,
                different ? explainers.by(dimension) : null, observed, null);
    }

    /** How the request's value was seen, when the view counted that same value (W5-10 D1~D3). */
    private static BaselineView.Seen seenOf(BaselineView view, String dimension, String value) {
        BaselineView.Seen seen = view != null && view.counts() != null ? view.counts().request().get(dimension) : null;
        return seen != null && value != null && value.equals(seen.value()) ? seen : null;
    }

    /** Why a dimension was not compared (W5-10 D1). */
    private static String notComparedReason(boolean windowObserved, Object value, boolean usualHeld) {
        return !windowObserved ? "no observations in the window"
                : value == null ? "the request does not state it"
                : usualHeld ? null : "no observation holds it";
    }

    private static Deviation.Explanation explain(DeviationDimension dimension, Explainers explainers) {
        if (explainers.by(dimension) != null) {
            return Deviation.Explanation.EXPLAINED;
        }
        return explainers.established() ? Deviation.Explanation.UNEXPLAINED : Deviation.Explanation.NOT_ESTABLISHED;
    }

    /**
     * What may explain a difference: the record covering the work, and the trip holding the request address. A
     * difference nothing explains is unexplained only against an established personal baseline, the one BaselineStatus
     * calls ESTABLISHED; while the baseline is learned it is stated as such (LU-1).
     */
    private record Explainers(String coveringRecord, String trip, boolean established) {

        String by(DeviationDimension dimension) {
            return switch (dimension.explainer()) {
                case COVERING_RECORD -> coveringRecord;
                case TRAVEL -> trip;
                case NONE -> null;
            };
        }
    }

    private static Explainers explainers(CanonicalSecurityContext context, CompanyRecordsEvaluator.Evaluation records,
                                         BaselineEvidenceSnapshot personal) {
        String covering = records.covering().map(RecordCheck::recordId).orElse(null);
        TravelRecord travel = context.getFrictionProfile() != null ? context.getFrictionProfile().getTravel() : null;
        String trip = travel != null && Boolean.TRUE.equals(tripHoldsAddress(travel, clientIp(context)))
                ? "trip " + (StringUtils.hasText(travel.getPlanId()) ? travel.getPlanId() : "registered by the host")
                : null;
        boolean established = personal != null && personal.status() == BaselineEvidenceStatus.AVAILABLE
                && personal.established();
        return new Explainers(covering, trip, established);
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

    private static void deviationFacts(Facts facts, List<Deviation> deviations, LearningContextEvidence evidence,
                                       Instant requestAt, ZoneId zone) {
        List<Deviation> compared = deviations.stream().filter(Deviation::compared).toList();
        if (compared.isEmpty()) {
            // The baseline learning exists but has nothing to compare with yet (dictionary 1.4 unavailable-now).
            String reason = evidence == null || evidence.baselineView() == null || !evidence.baselineView().observed()
                    ? "no learned baseline" : "no dimension compared";
            facts.unavailable(DEVIATIONS_FROM_BASELINE, reason);
            facts.unavailable(SAME_AS_BASELINE, reason);
            return;
        }
        List<Deviation> different = compared.stream().filter(Deviation::different).toList();
        StringBuilder value = new StringBuilder()
                .append(different.size()).append(" of ").append(compared.size()).append(" compared");
        if (!different.isEmpty()) {
            value.append(" -> ").append(different.stream().map(deviation -> deviation.describe(requestAt, zone))
                    .collect(Collectors.joining("; ")));
        }
        // W5-10 D1: a dimension not compared says why.
        List<Deviation> notCompared = deviations.stream()
                .filter(deviation -> !deviation.compared() && deviation.notComparedReason() != null).toList();
        if (!notCompared.isEmpty()) {
            value.append("; not compared: ").append(notCompared.stream()
                    .map(deviation -> deviation.dimension().label() + " (" + deviation.notComparedReason() + ")")
                    .collect(Collectors.joining(", ")));
        }
        // The past records are read within the request's action family (W3-18), its target's first, and the counts
        // state how many are on its target; the closest one read is compared on the hour, the login method and the
        // browser (P2 correction 3).
        String overlap = evidence != null ? evidence.currentRequestClosestOverlapOutsideRetrievalScope() : null;
        if (overlap != null && overlap.contains("/")) {
            value.append("; closest of the past records read for this action matches ")
                    .append(overlap.replace("/", " of ")).append(" on time, login method and browser");
        }
        List<String> explaining = different.stream().map(Deviation::explainedBy).filter(StringUtils::hasText)
                .distinct().toList();
        facts.add(DEVIATIONS_FROM_BASELINE, value.toString(),
                different.stream().map(deviation -> deviation.dimension().code()).toList(), explaining,
                DecisionFact.COMPUTED);
        List<Deviation> same = compared.stream().filter(deviation -> !deviation.different()).toList();
        facts.add(SAME_AS_BASELINE, same.isEmpty() ? "none"
                        : same.stream().map(deviation -> deviation.describe(requestAt, zone))
                        .collect(Collectors.joining("; ")),
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
                String line = describeApproval(record, check, request.at(), zone);
                if (!lines.contains(line)) {
                    lines.add(line);
                }
            }
            facts.add(APPROVAL, String.join("; ", lines),
                    records.approvals().stream().anyMatch(RecordCheck::valid) ? List.of("APPROVAL_COVERS") : List.of(),
                    records.approvals().stream().map(RecordCheck::recordId).distinct().toList(), DecisionFact.HOST);
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
                // A record the host states twice (found and named by the requester) is one line (LU-3).
                String line = describeTicket(record, check, request.at(), zone);
                if (!lines.contains(line)) {
                    lines.add(line);
                }
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
                        + (onCall.getEndsAt() != null
                        ? " until " + CompanyRecordsEvaluator.wallClock(onCall.getEndsAt(), request.at(), zone) : "")
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

    static String describeApproval(ApprovalRecord record, RecordCheck check, Instant at, ZoneId zone) {
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
                // Without the host's count the core counted this session only (LU-2).
                appendPart(text, "used " + CompanyRecordsEvaluator.number(check.usedBefore())
                        + (record.getUsedItems() != null ? " before this request" : " in this session before this request"));
            }
            if (record.getValidFrom() != null || record.getValidUntil() != null) {
                appendPart(text, "valid " + CompanyRecordsEvaluator.window(record.getValidFrom(), record.getValidUntil(),
                        at, zone));
            }
            appendPart(text, record.getDecidedAt() != null
                    ? "decided " + CompanyRecordsEvaluator.wallClock(record.getDecidedAt(), at, zone)
                    : "decision time not recorded (a decision after this request is not ruled out)");
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

    static String describeTicket(TicketRecord record, RecordCheck check, Instant at, ZoneId zone) {
        // A ticket the requester names is the requester's text: it is drawn once, as an untrusted text (N-INJ-1).
        if (check.claimFalse()) {
            return "the ticket named by the requester does not exist";
        }
        boolean claimed = record != null && Boolean.TRUE.equals(record.getClaimedByRequester());
        StringBuilder text = new StringBuilder(claimed ? "the ticket named by the requester" : check.recordId());
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
                appendPart(text, "valid " + CompanyRecordsEvaluator.window(record.getValidFrom(), record.getValidUntil(),
                        at, zone));
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
            // The target's values are the requester's text (N-INJ-1): the repeat says 'this target'.
            return "first " + what + (request.target() != null ? " of this target" : "") + " in this session";
        }
        StringBuilder text = new StringBuilder(ordinal(sameAction.size() + 1)).append(' ').append(what)
                .append(" in this session");
        if (request.target() != null) {
            List<SessionDecisionRecord> sameTarget = sameAction.stream()
                    .filter(decision -> request.target().equals(decision.target())).toList();
            if (!sameTarget.isEmpty()) {
                text.append(", ").append(sameTarget.size()).append(" earlier of the same target");
                int exported = sameTarget.stream()
                        .filter(decision -> decision.items() != null
                                && ALLOW.equalsIgnoreCase(String.valueOf(decision.outcome())))
                        .mapToInt(SessionDecisionRecord::items).sum();
                if (exported > 0) {
                    text.append("; ").append(CompanyRecordsEvaluator.number(exported))
                            .append(" items exported to the same target before this request");
                }
            }
        }
        return text.toString();
    }

    private static void roleScope(Facts facts, CanonicalSecurityContext context) {
        RoleScopeProfile scope = context.getRoleScopeProfile();
        if (scope == null) {
            facts.unknown(ROLE_SCOPE);
            return;
        }
        if (scope.getExpectedActionFamilies().isEmpty() && scope.getExpectedResourceFamilies().isEmpty()
                && scope.getActionFamilyDrift() == null && scope.getResourceFamilyDrift() == null) {
            // W5-10 D8: the lists are the other members'; without any the group has none to give.
            facts.unavailable(ROLE_SCOPE, Integer.valueOf(0).equals(scope.getPeerCount())
                    ? "no peers besides the user" : "no scope group lists yet");
            return;
        }
        List<String> parts = new ArrayList<>();
        String action = StringUtils.hasText(scope.getCurrentActionFamily()) ? scope.getCurrentActionFamily()
                : action(context, null);
        // A drift the host stated stands; without one the facts compare the request with the scope group's lists the way
        // the role scope collector does (ignoring case), since the core states no drift of its own (P2 correction 8).
        Boolean actionOutside = scope.getActionFamilyDrift() != null ? scope.getActionFamilyDrift()
                : action != null && !scope.getExpectedActionFamilies().isEmpty()
                ? scope.getExpectedActionFamilies().stream().noneMatch(expected -> action.trim().equalsIgnoreCase(
                        expected == null ? "" : expected.trim())) : null;
        String category = scope.getCurrentResourceFamily();
        Boolean categoryOutside = scope.getResourceFamilyDrift() != null ? scope.getResourceFamilyDrift()
                : StringUtils.hasText(category) && !scope.getExpectedResourceFamilies().isEmpty()
                ? scope.getExpectedResourceFamilies().stream().noneMatch(expected -> category.trim().equalsIgnoreCase(
                        expected == null ? "" : expected.trim())) : null;
        if (action != null && !scope.getExpectedActionFamilies().isEmpty()) {
            parts.add("action " + action + (Boolean.TRUE.equals(actionOutside) ? " outside" : " within")
                    + " the scope group's actions (" + String.join(", ", scope.getExpectedActionFamilies()) + ")");
        }
        // The role scope compares business categories, not the resource's class (W2-10).
        if (StringUtils.hasText(category) && !scope.getExpectedResourceFamilies().isEmpty()) {
            parts.add("category " + category
                    + (Boolean.TRUE.equals(categoryOutside) ? " outside" : " within")
                    + " the scope group's categories (" + String.join(", ", scope.getExpectedResourceFamilies()) + ")");
        }
        if (Boolean.TRUE.equals(scope.getCurrentActionFamilyInDeniedScope())) {
            parts.add("action in the scope group's denied actions");
        }
        if (Boolean.TRUE.equals(scope.getCurrentResourceFamilyInDeniedScope())) {
            parts.add("category in the scope group's denied categories");
        }
        boolean outside = Boolean.TRUE.equals(actionOutside)
                || Boolean.TRUE.equals(categoryOutside)
                || Boolean.TRUE.equals(scope.getCurrentActionFamilyInDeniedScope())
                || Boolean.TRUE.equals(scope.getCurrentResourceFamilyInDeniedScope());
        if (parts.isEmpty()) {
            facts.unavailable(ROLE_SCOPE, "nothing to compare in this request");
            return;
        }
        // W5-10 D8: how many other members the group's lists come from.
        if (scope.getPeerCount() != null && scope.getPeerCount() > 0) {
            parts.add("scope group of " + scope.getPeerCount()
                    + (scope.getPeerCount() == 1 ? " other user" : " other users"));
        }
        // The evidence state the dictionary entry names (LU-1): lists of thin or inferred evidence are provisional.
        if (CanonicalContextFieldPolicy.hasProvisionalRoleScopeProfile(context)) {
            parts.add("evidence PROVISIONAL");
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
        // A profile without any cohort fact (only a summary anchored to the department name) is no cohort source
        // (N-MISS-1 D4).
        if (cohort == null || !hasCohortFact(cohort)) {
            facts.unknown(PEER_COHORT);
            return;
        }
        if (cohort.getPreferredActionFamilies().isEmpty() && cohort.getPreferredResources().isEmpty()
                && cohort.getOutlierAgainstCohort() == null) {
            facts.unavailable(PEER_COHORT, "no cohort comparison data yet");
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

    /** Whether a cohort source gave the profile a fact: its id, its usual lists or bands, or the outlier mark. */
    private static boolean hasCohortFact(PeerCohortProfile cohort) {
        return StringUtils.hasText(cohort.getCohortId())
                || !cohort.getPreferredActionFamilies().isEmpty()
                || !cohort.getPreferredResources().isEmpty()
                || StringUtils.hasText(cohort.getNormalProtectableFrequencyBand())
                || StringUtils.hasText(cohort.getNormalSensitivityBand())
                || cohort.getOutlierAgainstCohort() != null;
    }

    /**
     * The move the host measured, beside its own impossible-travel yes or no (W2-13). Stated only when the host gives a
     * move; the parts it leaves out are named unknown.
     */
    private static void movement(Facts facts, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Location location = context.getLocation();
        CanonicalSecurityContext.Movement movement = location != null ? location.getMovement() : null;
        if (movement == null) {
            return;
        }
        String previous = StringUtils.hasText(movement.getPreviousLocation())
                ? movement.getPreviousLocation() : "an unknown previous location";
        String current = currentPlace(location, movement);
        String distance = movement.getDistanceKm() != null ? movement.getDistanceKm() + " km" : "an unknown distance";
        String elapsed = movement.getElapsedMinutes() != null ? movement.getElapsedMinutes() + " min" : "an unknown time";
        StringBuilder value = new StringBuilder(previous + " -> " + current + " " + distance + " in " + elapsed);
        if (movement.getBaselineConfidence() != null) {
            value.append("; location baseline confidence ").append(movement.getBaselineConfidence());
        }
        Boolean impossible = context.getIntent() != null ? context.getIntent().getImpossibleTravel() : null;
        if (impossible != null) {
            value.append(impossible ? "; the host states an impossible travel" : "; the host states no impossible travel");
        }
        // W4-8 (5): the contract's code for a stated move (dictionary 5: valid when the move fact is there).
        facts.add(MOVEMENT, value.toString(), List.of("DEVIATION_MOVEMENT"), List.of(), DecisionFact.HOST);
    }

    /**
     * A change of device or of network within the session, against the client the session first came from (W2-14).
     * Stated only when the session narrative found one.
     */
    private static void sessionClientChanges(Facts facts, CanonicalSecurityContext context) {
        CanonicalSecurityContext.SessionNarrativeProfile narrative = context.getSessionNarrativeProfile();
        if (narrative == null) {
            return;
        }
        if (StringUtils.hasText(narrative.getSessionDeviceChange())) {
            facts.add(SESSION_DEVICE_CHANGE, narrative.getSessionDeviceChange() + " in the same session",
                    List.of("SESSION_DEVICE_CHANGE"), List.of(), DecisionFact.COMPUTED);
        }
        if (StringUtils.hasText(narrative.getSessionNetworkChange())) {
            facts.add(SESSION_NETWORK_CHANGE, narrative.getSessionNetworkChange() + " in the same session",
                    List.of("SESSION_NETWORK_CHANGE"), List.of(), DecisionFact.COMPUTED);
        }
    }

    private static String currentPlace(CanonicalSecurityContext.Location location, CanonicalSecurityContext.Movement movement) {
        List<String> names = new ArrayList<>();
        if (StringUtils.hasText(location.getCity())) {
            names.add(location.getCity());
        }
        if (StringUtils.hasText(location.getCountry())) {
            names.add(location.getCountry());
        }
        if (!names.isEmpty()) {
            return String.join(", ", names);
        }
        if (movement.getLatitude() != null && movement.getLongitude() != null) {
            return movement.getLatitude() + "," + movement.getLongitude();
        }
        return "an unknown current location";
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
            String name = SecuritySemanticNormalizer.normalizeResourceClass(entry.substring(0, split));
            if (name != null && value != null) {
                counts.merge(name, value, Integer::sum);
            }
        }
        return counts;
    }

    /**
     * The usual login whose every method the request's login holds: the same login when it was seen, else the most
     * seen such usual login, the first by name among equals (W5-10 D6, P5-변경-17); null when there is none.
     */
    private static String usualLoginHeld(String login, Map<String, Integer> usualLogins) {
        if (usualLogins == null || usualLogins.isEmpty()) {
            return null;
        }
        if (usualLogins.containsKey(login)) {
            return login;
        }
        List<String> methods = SecuritySemanticNormalizer.loginMethods(login);
        String held = null;
        int heldCount = -1;
        for (Map.Entry<String, Integer> usual : usualLogins.entrySet()) {
            List<String> usualMethods = SecuritySemanticNormalizer.loginMethods(usual.getKey());
            int seen = usual.getValue() != null ? usual.getValue() : 0;
            if (!usualMethods.isEmpty() && methods.containsAll(usualMethods)
                    && (seen > heldCount || seen == heldCount && usual.getKey().compareTo(held) < 0)) {
                held = usual.getKey();
                heldCount = seen;
            }
        }
        return held;
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
        private final Map<String, String> unavailable = new LinkedHashMap<>();

        void add(String name, String value, String source) {
            add(name, value, List.of(), List.of(), source);
        }

        void add(String name, String value, List<String> codes, List<String> recordIds, String source) {
            if (!StringUtils.hasText(value)) {
                unknown(name);
                return;
            }
            // The fact ID is the one the prompt draws (W3-13, DecisionFacts.withPromptIds).
            known.add(new DecisionFact(null, name, value, codes, recordIds, source));
        }

        void unknown(String name) {
            if (!unknown.contains(name)) {
                unknown.add(name);
            }
        }

        /** An unknown fact whose source could not give it for this request (dictionary 1.4 unavailable-now). */
        void unavailable(String name, String reason) {
            unknown(name);
            unavailable.put(name, reason);
        }
    }
}
