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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.security.bridge.AgentConfirmationFacts;
import io.contexa.contexacommon.security.bridge.CredentialFacts;
import io.contexa.contexacommon.security.subject.SubjectKind;
import io.contexa.contexacore.autonomous.agent.AgentConfirmation;
import io.contexa.contexacore.autonomous.baseline.AgentBaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.support.SessionExports;
import io.contexa.contexacore.autonomous.context.decision.RelativeTime;
import io.contexa.contexacore.autonomous.context.enricher.RecordedDelegationContextProvider;
import io.contexa.contexacore.autonomous.context.enricher.RecordsHolder;
import io.contexa.contexacore.autonomous.event.support.InvocationArguments;
import io.contexa.contexacore.autonomous.execution.ExecutionSubject;
import io.contexa.contexacore.autonomous.execution.ExecutionSubjectTypes;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The v21 lines about agents and credentials (docs/agent A2): the credential a token states (A2-11), the delegation a
 * request runs under (A2-4), the work done so far in an agent's session (A2-9) and who wrote the records the request
 * rests on (A2-10). Each line states records and comparisons, never what they mean; the render and the prompt inspector
 * draw them with these same functions from the sealed context.
 */
public final class AgentLineValues {

    /** The comparison outcomes of the objective comparison, as its facts begin (ObjectiveDriftEvaluator). */
    private static final List<String> COMPARISON_OUTCOMES = List.of("Current action family is",
            "Current action family has no", "Current resource family is", "Current resource matches",
            "Current resource does not match", "Containment-only", "Delegated scope evidence marks");
    /** The instruction a coverage warning may end with, which a v21 line leaves out (A2-6). */
    private static final List<String> COVERAGE_INSTRUCTIONS = List.of(
            "any ALLOW conclusion must explain why the request is still acceptable");
    private static final String DELEGATION_MISSING = "Bridge missing context: DELEGATION.";
    private static final String DELEGATION_HINT_START = "If delegated agents are used";
    /** How the coverage evaluator's facts and warnings about a delegated objective begin (ContextCoverageEvaluator). */
    private static final String DELEGATED_OBJECTIVE = "Delegated objective";
    /** The kind of executing subject the publisher states (CanonicalExecutionEventMetadataSupport). */
    private static final String SUBJECT_KIND = "executionSubjectKind";

    private AgentLineValues() {
    }

    /**
     * {@code delegated access token, grant token-exchange, client report-agent, issued 2 min before this request,
     * expires 28 min after this request, actor chain depth 1, not bound to a key}: what the request's access token
     * states, or null for a session's request (A2-11). The token's times are on the issuer's clock, so they are told
     * against when the resource server read the token; only without that time against the request time.
     */
    @Nullable
    public static String credential(@Nullable Map<String, Object> attributes, @Nullable Instant at) {
        String kind = attributes != null ? text(attributes.get(CredentialFacts.KIND)) : null;
        if (kind == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        parts.add(switch (kind) {
            case CredentialFacts.USER_TOKEN -> "user access token";
            case CredentialFacts.DELEGATED_TOKEN -> "delegated access token";
            case CredentialFacts.CLIENT_TOKEN -> "client's own access token";
            default -> kind.toLowerCase(Locale.ROOT).replace('_', ' ');
        });
        add(parts, "grant ", text(attributes.get(CredentialFacts.GRANT)));
        add(parts, "client ", text(attributes.get(CredentialFacts.CLIENT_ID)));
        Instant checked = instant(attributes.get(CredentialFacts.CHECKED_AT));
        Instant reference = checked != null ? checked : at;
        add(parts, "issued ", RelativeTime.of(instant(attributes.get(CredentialFacts.ISSUED_AT)), reference));
        add(parts, "expires ", RelativeTime.of(instant(attributes.get(CredentialFacts.EXPIRES_AT)), reference));
        int depth = integer(attributes.get(CredentialFacts.CHAIN_DEPTH));
        if (depth > 0) {
            List<String> prior = strings(attributes.get(CredentialFacts.PRIOR_ACTORS));
            parts.add("actor chain depth " + depth + (prior.isEmpty() ? "" : " (before it: " + String.join(", ", prior) + ")"));
        }
        String binding = text(attributes.get(CredentialFacts.BINDING));
        parts.add(binding == null ? "not bound to a key"
                : CredentialFacts.BINDING_DPOP.equals(binding) ? "bound to a DPoP key" : "bound to an " + binding);
        return String.join(", ", parts);
    }

    /**
     * {@code approved by alice 0 min before this request, asked 2 min before this request because the delegation had
     * ended, for this request only, authorization ctxa-as:5c1d…}: the confirmation the accountable person gave for this
     * very request, or null (docs/agent F-5, A5-2). The confirmation's times are on the engine's clock, so they are told
     * against when the request used it, not against the request time a host may have recorded.
     */
    @Nullable
    public static String confirmation(@Nullable Map<String, Object> attributes) {
        String id = attributes != null ? text(attributes.get(AgentConfirmationFacts.ID)) : null;
        if (id == null) {
            return null;
        }
        Instant used = instant(attributes.get(AgentConfirmationFacts.USED_AT));
        String approved = RelativeTime.of(instant(attributes.get(AgentConfirmationFacts.DECIDED_AT)), used);
        String asked = RelativeTime.of(instant(attributes.get(AgentConfirmationFacts.ASKED_AT)), used);
        return "approved by " + orNotStated(text(attributes.get(AgentConfirmationFacts.DECIDED_BY)))
                + (approved != null ? " " + approved : "")
                + ", asked " + (asked != null ? asked + " " : "")
                + "because " + askedBecause(text(attributes.get(AgentConfirmationFacts.TRIGGER)))
                + ", for this request only, authorization "
                + firstText(text(attributes.get(AgentConfirmationFacts.AUTHORIZATION_ID)), "not recorded");
    }

    private static String askedBecause(@Nullable String trigger) {
        if (trigger == null) {
            return "not stated";
        }
        return switch (trigger) {
            case AgentConfirmation.DELEGATION_ENDED -> "the delegation had ended";
            case AgentConfirmation.DECISION_CHALLENGE -> "the decision in force asked for a check";
            case AgentConfirmation.REQUESTED -> "the agent asked for it";
            default -> trigger.toLowerCase(Locale.ROOT).replace('_', ' ');
        };
    }

    /**
     * {@code agent report-agent for alice, chain depth 1, objective REPORTING, allowed READ on HX-310, expires 3 h after
     * this request, proof signed token claim and delegation record, drift no (Current action family is listed ...)}:
     * the delegation of a delegated request, or null (A2-4). The objective's free text is not in it (A2-5).
     */
    @Nullable
    public static String delegation(@Nullable CanonicalSecurityContext context, @Nullable Instant at) {
        CanonicalSecurityContext.Delegation delegation = context != null ? context.getDelegation() : null;
        if (delegation == null || !delegation.hasMandate()) {
            return null;
        }
        Map<String, Object> attributes = attributes(context);
        CanonicalSecurityContext.Actor actor = context.getActor();
        // RL-10: a standing delegation is the agent's sponsor's; the actor is the agent itself.
        String delegator = Boolean.TRUE.equals(delegation.getStanding())
                ? firstText(text(attributes.get("agentSponsorId")), text(attributes.get("delegatorId")))
                : firstText(text(attributes.get("delegatorId")), actor != null ? actor.getUserId() : null);
        int depth = integer(attributes.get("delegationChainDepth"));
        if (depth == 0) {
            depth = Math.max(1, integer(attributes.get(CredentialFacts.CHAIN_DEPTH)));
        }
        String expires = RelativeTime.of(instant(delegation.getExpiresAt()), at);
        Boolean drift = delegation.getObjectiveDrift();
        List<String> outcomes = comparisonOutcomes(delegation.getObjectiveDriftSummary());
        return "agent " + orNotStated(delegation.getAgentId())
                + " for " + orNotStated(delegator)
                + ", chain depth " + depth
                + ", objective " + orNotStated(firstText(delegation.getObjectiveFamily(), delegation.getObjectiveId()))
                + ", allowed " + listed(delegation.getAllowedOperations(), "any operation")
                + " on " + listed(delegation.getAllowedResources(), "any resource")
                + ", expires " + (expires != null ? expires : "not stated")
                + limits(delegation)
                + ", proof " + proof(attributes)
                + ", drift " + (drift == null ? "not compared" : drift ? "yes" : "no")
                + " (" + (outcomes.isEmpty() ? "no comparable action or resource" : String.join("; ", outcomes)) + ")";
    }

    /**
     * {@code , limits 40 items per request and 40 items in the session}: the quantity limits the delegation states, or
     * nothing when it states none (RL-6).
     */
    private static String limits(CanonicalSecurityContext.Delegation delegation) {
        Integer perRequest = delegation.getMaxItemsPerRequest();
        Integer total = delegation.getMaxItemsTotal();
        if (perRequest == null && total == null) {
            return "";
        }
        List<String> limits = new ArrayList<>();
        if (perRequest != null) {
            limits.add(String.format(Locale.ROOT, "%,d", perRequest) + " items per request");
        }
        if (total != null) {
            limits.add(String.format(Locale.ROOT, "%,d", total) + " items in the session");
        }
        return ", limits " + String.join(" and ", limits);
    }

    /**
     * {@code 7 earlier requests in this agent session (READ 5, EXPORT 2), 1,240 items exported, 6 distinct targets,
     * 1 refused, first 12 min before this request}: what an agent has done in its session (a delegation's, A1-11), or
     * null for a person's request and without the session's decisions (A2-9).
     */
    @Nullable
    public static String delegationActivity(@Nullable CanonicalSecurityContext context, @Nullable Instant at) {
        CanonicalSecurityContext.SessionNarrativeProfile narrative =
                context != null ? context.getSessionNarrativeProfile() : null;
        if (!agentRequest(context) || narrative == null || narrative.getSessionDecisions() == null) {
            return null;
        }
        List<SessionDecisionRecord> decisions = narrative.getSessionDecisions().stream().filter(Objects::nonNull).toList();
        if (decisions.isEmpty()) {
            return "no earlier request in this agent session";
        }
        Map<String, Integer> byAction = new LinkedHashMap<>();
        Set<String> targets = new LinkedHashSet<>();
        int refused = 0;
        Instant first = null;
        for (SessionDecisionRecord decision : decisions) {
            byAction.merge(firstText(decision.actionFamily(), "UNKNOWN"), 1, Integer::sum);
            if (StringUtils.hasText(decision.target())) {
                targets.add(decision.target().trim());
            }
            if (!SessionExports.ran(decision)) {
                refused++;
            }
            if (decision.at() != null && (first == null || decision.at().isBefore(first))) {
                first = decision.at();
            }
        }
        List<String> actions = new ArrayList<>();
        byAction.forEach((action, count) -> actions.add(action + " " + count));
        List<String> parts = new ArrayList<>();
        parts.add(decisions.size() + " earlier request" + (decisions.size() == 1 ? "" : "s")
                + " in this agent session (" + String.join(", ", actions) + ")");
        parts.add(String.format(Locale.ROOT, "%,d", SessionExports.exportedItems(context)) + " items exported");
        parts.add(targets.size() + " distinct target" + (targets.size() == 1 ? "" : "s"));
        parts.add(refused + " refused");
        add(parts, "first ", RelativeTime.of(first, at));
        // A4-5: the order of the session's latest requests and the usual time between them.
        add(parts, "order ", order(decisions));
        add(parts, "median ", medianInterval(decisions, at));
        return String.join(", ", parts);
    }

    /** The most earlier requests whose order the activity line states. */
    static final int ORDER_LENGTH = 10;

    /**
     * {@code LIST, READ x5, EXPORT (last 7)}: the operations of the session's latest requests in the order made, a run
     * of the same operation as one with its count, or null without any (A4-5).
     */
    @Nullable
    static String order(List<SessionDecisionRecord> decisions) {
        List<SessionDecisionRecord> latest = decisions.size() > ORDER_LENGTH
                ? decisions.subList(decisions.size() - ORDER_LENGTH, decisions.size()) : decisions;
        if (latest.isEmpty()) {
            return null;
        }
        List<String> runs = new ArrayList<>();
        String current = null;
        int count = 0;
        for (SessionDecisionRecord decision : latest) {
            String action = firstText(decision.actionFamily(), "UNKNOWN");
            if (action.equals(current)) {
                count++;
                continue;
            }
            if (current != null) {
                runs.add(count > 1 ? current + " x" + count : current);
            }
            current = action;
            count = 1;
        }
        runs.add(count > 1 ? current + " x" + count : current);
        return String.join(", ", runs) + " (last " + latest.size() + ")";
    }

    /**
     * {@code 2 s between requests}: the median time between the session's requests, this request included, or null
     * when fewer than two of them have a time (A4-5).
     */
    @Nullable
    static String medianInterval(List<SessionDecisionRecord> decisions, @Nullable Instant at) {
        List<Instant> times = new ArrayList<>();
        for (SessionDecisionRecord decision : decisions) {
            if (decision.at() != null) {
                times.add(decision.at());
            }
        }
        if (at != null) {
            times.add(at);
        }
        if (times.size() < 2) {
            return null;
        }
        times.sort(Instant::compareTo);
        List<Long> gaps = new ArrayList<>();
        for (int index = 1; index < times.size(); index++) {
            gaps.add(Math.max(0, times.get(index).getEpochSecond() - times.get(index - 1).getEpochSecond()));
        }
        gaps.sort(Long::compareTo);
        long median = gaps.size() % 2 == 1 ? gaps.get(gaps.size() / 2)
                : (gaps.get(gaps.size() / 2 - 1) + gaps.get(gaps.size() / 2)) / 2;
        return (median < 120 ? median + " s" : median / 60 + " min") + " between requests";
    }

    /**
     * {@code agent report-agent acting for alice, learned from this agent's own requests}: whose usual behaviour the
     * baseline lines of an agent's request state (A3-1, A4-3), or null for a person's request.
     */
    @Nullable
    public static String baselineSubject(@Nullable CanonicalSecurityContext context) {
        Agent agent = agent(context);
        if (agent == null) {
            return null;
        }
        CanonicalSecurityContext.Actor actor = context.getActor();
        String person = actor != null ? text(actor.getUserId()) : null;
        return "agent " + agent.id() + (agent.delegated() && person != null ? " acting for " + person : " on its own")
                + ", learned from this agent's own requests";
    }

    /**
     * {@code LIST>READ 3, READ>READ 12; this request READ>EXPORT seen 1 time before}: which operation usually follows
     * which in the agent's sessions and whether this request's pair was seen (A4-1), or null for a person's request
     * and before the agent has learned requests.
     */
    @Nullable
    public static String usualSequence(@Nullable CanonicalSecurityContext context) {
        AgentBaselineView view = agentBaseline(context);
        if (view == null) {
            return null;
        }
        String usual = view.usualTransitions().isEmpty() ? "none learned" : counts(view.usualTransitions());
        String current = view.currentTransition() == null ? "this request is its session's first operation"
                : "this request " + view.currentTransition() + " seen " + times(view.currentTransitionSeen()) + " before";
        return usual + "; " + current;
    }

    /**
     * {@code report-client #1a2b3c4d5e6f7a8b 18; this request report-client #1a2b3c4d5e6f7a8b seen 18 times before}:
     * the clients the agent usually calls from (its OAuth client and the digest of its user agent, A4-6) and whether
     * this request's was seen, or null for a person's request and before the agent has learned requests.
     */
    @Nullable
    public static String usualClients(@Nullable CanonicalSecurityContext context) {
        AgentBaselineView view = agentBaseline(context);
        if (view == null) {
            return null;
        }
        String usual = view.usualClients().isEmpty() ? "none learned" : counts(view.usualClients());
        String current = view.currentClient() == null ? "this request states no client"
                : "this request " + view.currentClient() + " seen " + times(view.currentClientSeen()) + " before";
        return usual + "; " + current;
    }

    /** The agent baseline of an agent's request, null for a person's request or without one. */
    @Nullable
    private static AgentBaselineView agentBaseline(@Nullable CanonicalSecurityContext context) {
        if (agent(context) == null || context.getWorkProfile() == null) {
            return null;
        }
        AgentBaselineView view = context.getWorkProfile().getAgentBaseline();
        return view != null && view.observed() ? view : null;
    }

    private static String counts(List<AgentBaselineView.Count> counts) {
        List<String> parts = new ArrayList<>();
        for (AgentBaselineView.Count count : counts) {
            parts.add(count.value() + " " + count.count());
        }
        return String.join(", ", parts);
    }

    private static String times(int count) {
        return count + (count == 1 ? " time" : " times");
    }

    /**
     * {@code approval APR-1 recorded by report-agent (this request's agent) 2 min before this request; delegation DLG-1
     * recorded by alice (the delegator) 1 h before this request}: who wrote the records the request rests on and when,
     * as the host states it, or null when it states it for none (A2-10).
     */
    @Nullable
    public static String recordProvenance(@Nullable CanonicalSecurityContext context, @Nullable Instant at) {
        if (context == null) {
            return null;
        }
        List<String> records = new ArrayList<>();
        CanonicalSecurityContext.FrictionProfile friction = context.getFrictionProfile();
        if (friction != null) {
            for (CanonicalSecurityContext.ApprovalRecord approval : nonNull(friction.getApprovalRecords())) {
                addRecord(records, context, at, "approval", approval.getApprovalId(), approval.getRecordedBy(),
                        approval.getRecordedAt());
            }
            for (CanonicalSecurityContext.TicketRecord ticket : nonNull(friction.getTicketRecords())) {
                addRecord(records, context, at, "ticket", ticket.getTicketId(), ticket.getRecordedBy(),
                        ticket.getRecordedAt());
            }
        }
        Map<String, Object> attributes = attributes(context);
        addRecord(records, context, at, "delegation",
                text(attributes.get(RecordedDelegationContextProvider.RECORD_ID_ATTRIBUTE)),
                text(attributes.get(RecordedDelegationContextProvider.RECORDED_BY_ATTRIBUTE)),
                instant(attributes.get(RecordedDelegationContextProvider.RECORDED_AT_ATTRIBUTE)));
        return records.isEmpty() ? null : String.join("; ", records);
    }

    /**
     * {@code v1-eng-k (the agent's sponsor)}: whose company records the request is judged with, when the host looked
     * them up for another person than the request's subject (A2-12), or null.
     */
    @Nullable
    public static String recordsHolder(@Nullable CanonicalSecurityContext context) {
        CanonicalSecurityContext.FrictionProfile friction = context != null ? context.getFrictionProfile() : null;
        String holder = friction != null ? text(friction.getRecordsHolderId()) : null;
        String relation = friction != null ? text(friction.getRecordsHolderRelation()) : null;
        if (holder == null || relation == null || RecordsHolder.SUBJECT.equals(relation)) {
            return null;
        }
        return switch (relation) {
            case RecordsHolder.DELEGATOR -> holder + " (the delegator)";
            case RecordsHolder.SPONSOR -> holder + " (the agent's sponsor)";
            default -> null;
        };
    }

    /** The delegation's objective as it was written (A2-5: an untrusted text), or null without a delegation. */
    @Nullable
    public static String delegationObjective(@Nullable CanonicalSecurityContext context) {
        CanonicalSecurityContext.Delegation delegation = context != null ? context.getDelegation() : null;
        return delegation != null && delegation.hasMandate()
                ? text(delegation.getObjectiveSummary()) : null;
    }

    /** The summary of the protected method's call arguments (A2-8: an untrusted text), or null. */
    @Nullable
    public static String callArguments(@Nullable CanonicalSecurityContext context) {
        return context != null ? text(attributes(context).get(InvocationArguments.KEY)) : null;
    }

    /** Whether the delegation names its agent, its objective and a scope, after the records were read (A2-6). */
    public static boolean delegationComplete(@Nullable CanonicalSecurityContext context) {
        CanonicalSecurityContext.Delegation delegation = context != null ? context.getDelegation() : null;
        return delegation != null && delegation.hasMandate()
                && StringUtils.hasText(delegation.getAgentId())
                && (StringUtils.hasText(delegation.getObjectiveFamily()) || StringUtils.hasText(delegation.getObjectiveId())
                        || StringUtils.hasText(delegation.getObjectiveSummary()))
                && (!nonNull(delegation.getAllowedOperations()).isEmpty() || !nonNull(delegation.getAllowedResources()).isEmpty());
    }

    /**
     * Whether a v21 coverage line keeps a fact or a warning of the coverage report (A2-6, flow map 6.6): the delegation
     * line and the coverage line state one delegation. The bridge's missing delegation is left out once the delegation's
     * records completed it, and what the report says of a delegated objective is left out for a request that is not
     * delegated (an agent on its own, whose agent id alone made the evaluator read a delegation).
     */
    public static boolean keepsCoverageFact(@Nullable String fact, @Nullable CanonicalSecurityContext context) {
        if (fact == null) {
            return false;
        }
        if (DELEGATION_MISSING.equals(fact)) {
            return !delegationComplete(context);
        }
        return !fact.startsWith(DELEGATED_OBJECTIVE) || delegated(context);
    }

    /** A bridge hint a v21 line keeps: the delegation hint is left out once the delegation is complete (A2-6). */
    public static boolean keepsHint(@Nullable String hint, @Nullable CanonicalSecurityContext context) {
        return hint != null && !(hint.startsWith(DELEGATION_HINT_START) && delegationComplete(context));
    }

    private static boolean delegated(@Nullable CanonicalSecurityContext context) {
        CanonicalSecurityContext.Delegation delegation = context != null ? context.getDelegation() : null;
        return delegation != null && delegation.hasMandate();
    }

    /** A coverage warning without an instruction after its fact (A2-6). */
    public static String warningFact(String warning) {
        if (warning == null) {
            return null;
        }
        String fact = warning;
        for (String instruction : COVERAGE_INSTRUCTIONS) {
            String tail = "; " + instruction + ".";
            if (fact.endsWith(tail)) {
                fact = fact.substring(0, fact.length() - tail.length()) + ".";
            }
        }
        return fact;
    }

    /**
     * The agent that sends the request, as the publisher states it (A1-6): its registration ID, whether it acts for a
     * person (a delegation) or on its own, its sponsor and its registration status; null for a person's request.
     */
    @Nullable
    public static Agent agent(@Nullable CanonicalSecurityContext context) {
        if (context == null) {
            return null;
        }
        Map<String, Object> attributes = attributes(context);
        String kind = text(attributes.get(SUBJECT_KIND));
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        boolean delegated = SubjectKind.DELEGATED_AGENT.name().equals(kind)
                || (delegation != null && Boolean.TRUE.equals(delegation.getDelegated()));
        if (!delegated && !SubjectKind.AUTONOMOUS_AGENT.name().equals(kind)) {
            return null;
        }
        String agentId = firstText(text(attributes.get("agentId")), delegation != null ? delegation.getAgentId() : null);
        if (agentId == null) {
            return null;
        }
        return new Agent(agentId, delegated, text(attributes.get("agentSponsorId")),
                text(attributes.get("agentRegistrationStatus")));
    }

    /** The agent of a request: registration ID, delegated or on its own, sponsor and registration status. */
    public record Agent(String id, boolean delegated, @Nullable String sponsorId, @Nullable String registration) {
    }

    /** Whether an agent sends the request, on its own or for a person (the publisher's subject kind or the subject). */
    private static boolean agentRequest(@Nullable CanonicalSecurityContext context) {
        if (context == null) {
            return false;
        }
        String kind = text(attributes(context).get(SUBJECT_KIND));
        if (SubjectKind.DELEGATED_AGENT.name().equals(kind) || SubjectKind.AUTONOMOUS_AGENT.name().equals(kind)) {
            return true;
        }
        ExecutionSubject subject = context.getExecutionSubject();
        return subject != null && ExecutionSubjectTypes.AGENT_RUNTIME.equals(subject.subjectType());
    }

    private static void addRecord(List<String> records, CanonicalSecurityContext context, @Nullable Instant at,
                                  String kind, @Nullable String id, @Nullable String recordedBy,
                                  @Nullable Instant recordedAt) {
        if (recordedBy == null && recordedAt == null) {
            return;
        }
        StringBuilder record = new StringBuilder(kind).append(' ').append(orNotStated(id)).append(" recorded");
        if (recordedBy != null) {
            record.append(" by ").append(recordedBy.trim());
            String who = who(context, recordedBy.trim());
            if (who != null) {
                record.append(" (").append(who).append(')');
            }
        } else {
            record.append(", author not stated,");
        }
        String when = RelativeTime.of(recordedAt, at);
        record.append(' ').append(when != null ? when : recordedAt == null ? "time not stated" : recordedAt.toString());
        records.add(record.toString());
    }

    /** Who a record's author is to this request: its agent, its delegator or its subject; null for anyone else. */
    @Nullable
    private static String who(CanonicalSecurityContext context, String author) {
        CanonicalSecurityContext.Delegation delegation = context.getDelegation();
        if (delegation != null && author.equals(text(delegation.getAgentId()))) {
            return "this request's agent";
        }
        if (author.equals(text(attributes(context).get("delegatorId")))) {
            return "the delegator";
        }
        CanonicalSecurityContext.Actor actor = context.getActor();
        if (actor != null && author.equals(text(actor.getUserId()))) {
            return "this request's subject";
        }
        return null;
    }

    private static String proof(Map<String, Object> attributes) {
        List<String> grades = new ArrayList<>();
        String state = text(attributes.get("delegationEvidenceState"));
        if (state != null) {
            grades.add(state.toLowerCase(Locale.ROOT).replace('_', ' '));
        }
        if ("FOUND".equals(text(attributes.get(RecordedDelegationContextProvider.LOOKUP_ATTRIBUTE)))) {
            grades.add("delegation record");
        }
        return grades.isEmpty() ? "not stated" : String.join(" and ", grades);
    }

    private static List<String> comparisonOutcomes(@Nullable String summary) {
        if (!StringUtils.hasText(summary)) {
            return List.of();
        }
        List<String> outcomes = new ArrayList<>();
        for (String part : summary.split(" \\| ")) {
            String fact = part.trim();
            boolean outcome = COMPARISON_OUTCOMES.stream().anyMatch(fact::startsWith)
                    || fact.matches("\\d+ requested items .+");
            if (outcome) {
                outcomes.add(fact.endsWith(".") ? fact.substring(0, fact.length() - 1) : fact);
            }
        }
        return outcomes;
    }

    private static String listed(@Nullable List<String> values, String none) {
        List<String> listed = nonNull(values).stream().filter(StringUtils::hasText).map(String::trim).toList();
        return listed.isEmpty() ? none : String.join("/", listed);
    }

    private static Map<String, Object> attributes(CanonicalSecurityContext context) {
        return context.getAttributes() != null ? context.getAttributes() : Map.of();
    }

    private static <T> List<T> nonNull(@Nullable List<T> values) {
        return values != null ? values : List.of();
    }

    private static void add(List<String> parts, String prefix, @Nullable String value) {
        if (StringUtils.hasText(value)) {
            parts.add(prefix + value.trim());
        }
    }

    private static String orNotStated(@Nullable String value) {
        return StringUtils.hasText(value) ? value.trim() : "not stated";
    }

    @Nullable
    private static String firstText(@Nullable String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
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

    private static int integer(@Nullable Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        String text = text(value);
        if (text == null) {
            return 0;
        }
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException notANumber) {
            return 0;
        }
    }

    private static List<String> strings(@Nullable Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(AgentLineValues::text).filter(Objects::nonNull).toList();
        }
        String text = text(value);
        return text == null ? List.of() : List.of(text.replace("[", "").replace("]", "").split(",\\s*"));
    }

    @Nullable
    private static Instant instant(@Nullable Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        String text = text(value);
        if (text == null) {
            return null;
        }
        try {
            return OffsetDateTime.parse(text).toInstant();
        } catch (RuntimeException notAnInstant) {
            return null;
        }
    }
}
