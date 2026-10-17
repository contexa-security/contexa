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

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.baseline.BaselineViewCalculator;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.Deviation;
import io.contexa.contexacore.autonomous.context.decision.DeviationDimension;
import io.contexa.contexacore.autonomous.context.decision.RelativeTime;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.model.ContextFieldTrustRecord;
import io.contexa.contexacore.autonomous.context.model.ContextTrustProfile;
import io.contexa.contexacore.autonomous.context.policy.ContextSemanticBoundaryPolicy;
import io.contexa.contexacore.autonomous.context.policy.ContextEvidenceGuidance;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptEntryValues;
import io.contexa.contexacore.autonomous.context.prompt.PromptListItem;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotRenderer;
import io.contexa.contexacore.autonomous.context.prompt.PromptUnknownKind;
import io.contexa.contexacore.autonomous.context.prompt.PromptListOrder;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.execution.ExecutionSubject;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import org.springframework.util.StringUtils;

import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.regex.Pattern;

/**
 * Fills the v20 dictionary entries of one request from the prompt's build context (W3-2). Each entry gets the facts the
 * v19 prompt carried for it, from the same computation (canonical context, baseline view, decision facts, session
 * records, retrieval state), in the vocabulary those sources use. An entry whose source states nothing has no value,
 * so the renderer draws the dictionary's missing notation; an entry whose source is missing altogether is marked
 * unknown, so that no missing notation claims what the engine cannot back. Aligning every value with its format
 * pattern is W3-12, the fact IDs W3-13, the form of a past record W3-3 and untrusted text W3-6.
 */
final class SecurityDecisionPromptValues {

    private static final PromptBlock BASELINE = PromptBlock.USER_BASELINE;
    private static final PromptBlock SESSION = PromptBlock.SESSION;
    private static final PromptBlock REQUEST = PromptBlock.REQUEST;
    private static final PromptBlock FACTS = PromptBlock.DECISION_FACTS;
    private static final PromptBlock PAST = PromptBlock.PAST_RECORDS;
    private static final PromptBlock UNKNOWN = PromptBlock.UNKNOWN;
    private static final PromptBlock UNTRUSTED = PromptBlock.UNTRUSTED_TEXT;
    /** What the target line says of the business label: where its text is (N-INJ-3, shared with the dictionary). */
    static final String TARGET_LABEL_NOTE = "business label in UNTRUSTED TEXT";
    /** A time of the event clock ({@code 03:17}) or a compared hour ({@code time 03 }) in a decision fact. */
    private static final Pattern ON_THE_CLOCK = Pattern.compile("\\b\\d{2}:\\d{2}\\b|\\btime \\d{2} ");

    private SecurityDecisionPromptValues() {
    }

    static PromptEntryValues of(SecurityDecisionPromptSections sections, SecurityPromptBuildContext context,
                                PromptEntryValues.Builder values, ZoneId zone) {
        CanonicalSecurityContext canonical = context.getCanonicalSecurityContext();
        LearningContextEvidence evidence = context.getLearningContextEvidence();
        Instant at = requestTime(context.getEvent(), canonical);
        values.timeZone(zone);
        userBaseline(sections, context, canonical, evidence, at, zone, values);
        session(context, canonical, at, zone, values);
        request(context, canonical, evidence, at, zone, values);
        decisionFacts(sections, context, canonical, values);
        pastRecords(sections, context, evidence, values);
        unknown(canonical, evidence != null ? evidence.baselineView() : null, values);
        untrustedText(sections, context, canonical, values);
        // N-INS-2 (R1b): the entries without a source are named unknown by the rule the inspector reads them with.
        for (String key : withoutSource(canonical)) {
            int dot = key.indexOf('.');
            values.unknown(PromptBlock.valueOf(key.substring(0, dot)), key.substring(dot + 1));
        }
        return values.build();
    }

    private static void userBaseline(SecurityDecisionPromptSections sections, SecurityPromptBuildContext context,
                                     CanonicalSecurityContext canonical, LearningContextEvidence evidence, Instant at,
                                     ZoneId zone, PromptEntryValues.Builder values) {
        BaselineView view = evidence != null ? evidence.baselineView() : null;
        BaselineEvidenceSnapshot personal = evidence != null ? evidence.personalBaseline() : null;
        // W3-19, Q-79 A1: the baseline state is one fact stated once, by the status line; the evidence line states the
        // evidence only and is not drawn without any.
        String status = baselineStatus(context.getBaselineStatus(), personal, view, evidence, canonical,
                sections.pastRecordCounts(context));
        values.value(BASELINE, "Evidence", baselineEvidence(canonical, view, at, zone));
        if (view != null && view.observed() && at != null) {
            // The window's dates are days of the event clock (W3-13).
            values.clocked(BASELINE, "Evidence");
        }
        values.value(BASELINE, "BaselineStatus", status);
        if (view != null && view.observed()) {
            Map<String, String> lines = viewLines(view);
            clockedValue(values, BASELINE, "UsualHours", lines.get("UsualHours"));
            clockedValue(values, BASELINE, "UsualDays", lines.get("UsualDays"));
            lines.forEach((name, value) -> {
                if (!"UsualHours".equals(name) && !"UsualDays".equals(name)) {
                    values.value(BASELINE, name, value);
                }
            });
            values.value(BASELINE, "WorkProfile", workProfile(canonical != null ? canonical.getWorkProfile() : null, view));
        }
        values.value(BASELINE, "UsualNetworks", names(view != null && !view.usualNetworks().isEmpty()
                ? view.usualNetworks() : personalNetworks(personal)));
        values.value(BASELINE, "UsualDevices", usualDevices(view, personal));
        values.value(BASELINE, "UsualLoginMethods", names(view != null && !view.usualLoginMethods().isEmpty()
                ? view.usualLoginMethods() : personalLoginMethods(personal)));
        CanonicalSecurityContext.WorkProfile workProfile = canonical != null ? canonical.getWorkProfile() : null;
        values.value(BASELINE, "SeasonalPattern", workProfile != null ? workProfile.getSeasonalBusinessProfile() : null);
        String peer = peerReference(sections, context, evidence);
        values.value(BASELINE, "PeerReference", peer);
        if (peer != null && (peer.contains("hours ") || peer.contains("days "))) {
            values.clocked(BASELINE, "PeerReference");
        }
    }

    private static void session(SecurityPromptBuildContext context, CanonicalSecurityContext canonical, Instant at,
                                ZoneId zone, PromptEntryValues.Builder values) {
        CanonicalSecurityContext.Session session = canonical != null ? canonical.getSession() : null;
        CanonicalSecurityContext.SessionNarrativeProfile narrative =
                canonical != null ? canonical.getSessionNarrativeProfile() : null;
        if (narrative != null && narrative.getSessionAgeMinutes() != null) {
            values.value(SESSION, "SessionAge", sessionAge(narrative.getSessionAgeMinutes(),
                    narrative.getSessionAgeBasis()));
        }
        values.value(SESSION, "LoginMethod", loginMethod(context, canonical, session, at));
        // Without a session the challenge is named unknown by withoutSource (N-INS-2).
        if (session != null) {
            Instant verified = parseInstant(session.getChallengeVerifiedAt());
            if (verified != null) {
                clockedValue(values, SESSION, "ChallengeVerified", challengeVerified(verified, at, zone));
            }
            values.value(SESSION, "RecentMfaElsewhere",
                    mfaElsewhere(parseInstant(session.getRecentMfaElsewhereAt()), at));
            values.value(SESSION, "FailedLogins", failedLogins(session));
            values.value(SESSION, "MfaFailures", mfaFailures(session));
            values.value(SESSION, "RecentRequests", recentRequests(session,
                    canonical != null ? canonical.getSessionNarrativeProfile() : null));
            values.value(SESSION, "ConcurrentSessions", concurrentSessions(session));
            values.value(SESSION, "PasswordAge", passwordAge(session));
        }
        // Without the session's decision history its requests are named unknown by withoutSource (N-INS-2).
        if (narrative != null && narrative.getSessionDecisions() != null) {
            values.value(SESSION, "RequestsInSession",
                    requestsInSession(narrative.getSessionDecisions(), currentTarget(canonical), at, zone));
            if (narrative.getSessionDecisions().stream().anyMatch(decision -> decision != null && decision.at() != null)) {
                values.clocked(SESSION, "RequestsInSession");
            }
        }
        CanonicalSecurityContext.ObservedScope scope = canonical != null ? canonical.getObservedScope() : null;
        values.value(SESSION, "RecentSensitiveAccess", recentSensitiveAccess(scope));
        values.value(SESSION, "RecentDenied",
                recentDenied(narrative != null ? narrative.getSessionDecisions() : null, scope, zone));
    }

    private static void request(SecurityPromptBuildContext context, CanonicalSecurityContext canonical,
                                LearningContextEvidence evidence, Instant at, ZoneId zone,
                                PromptEntryValues.Builder values) {
        CurrentLearningContextSnapshot current = evidence != null ? evidence.current() : null;
        CanonicalSecurityContext.Resource resource = canonical != null ? canonical.getResource() : null;
        CanonicalSecurityContext.Session session = canonical != null ? canonical.getSession() : null;
        values.value(REQUEST, "Subject", subject(context, canonical, at));
        values.value(REQUEST, "Roles", rolesLine(canonical));
        values.value(REQUEST, "Permissions", permissionsLine(canonical));
        if (at != null) {
            clockedValue(values, REQUEST, "Time", requestClock(at, zone));
        }
        values.value(REQUEST, "Action", action(context.getEvent(), resource, current));
        // Without a target the line is named unknown by withoutSource (N-INS-2).
        values.value(REQUEST, "Target", target(resource));
        values.value(REQUEST, "Size", requestedSize(resource != null ? resource.getRequestedItems() : null));
        values.value(REQUEST, "ResourceClass", resourceClass(resource));
        values.value(REQUEST, "Network", network(session, canonical != null ? canonical.getLocation() : null, current));
        values.value(REQUEST, "Device", device(context.getEvent(), canonical, current));
    }

    private static void decisionFacts(SecurityDecisionPromptSections sections, SecurityPromptBuildContext context,
                                      CanonicalSecurityContext canonical, PromptEntryValues.Builder values) {
        DecisionFacts facts = canonical != null ? canonical.getDecisionFacts() : null;
        // Without the computation the repeat and the differences are named unknown by withoutSource (N-INS-2).
        if (facts != null) {
            for (DecisionFact fact : facts.facts()) {
                if (has(FACTS, fact.name())) {
                    values.value(FACTS, fact.name(), fact.value());
                    // A record's time or a compared hour is on the event clock (W3-13).
                    if (fact.value() != null && ON_THE_CLOCK.matcher(fact.value()).find()) {
                        values.clocked(FACTS, fact.name());
                    }
                }
            }
            for (String name : facts.unknown()) {
                if (has(FACTS, name)) {
                    String reason = facts.unavailable().get(name);
                    if (PromptUnknownKind.ofReason(reason) == PromptUnknownKind.UNAVAILABLE_NOW) {
                        values.unknown(FACTS, name, PromptUnknownKind.UNAVAILABLE_NOW, reason);
                    }
                    else {
                        values.unknown(FACTS, name);
                    }
                }
            }
        }
        CanonicalSecurityContext.RoleScopeProfile roleScope = canonical != null ? canonical.getRoleScopeProfile() : null;
        if (roleScope != null) {
            values.value(FACTS, "RecentPermissionChanges", names(roleScope.getRecentPermissionChanges(), "; "));
            if (roleScope.getTemporaryElevation() != null) {
                values.value(FACTS, "TemporaryElevation", temporaryElevation(roleScope));
            }
        }
        values.value(FACTS, "AuthorizationEffect", authorizationEffect(context.getEvent(), canonical));
        CanonicalSecurityContext.Intent intent = canonical != null ? canonical.getIntent() : null;
        values.value(FACTS, "ClientSignals", clientSignals(intent));
        values.value(FACTS, "BlockedUser", blockedUser(canonical));
        values.value(FACTS, "BreakGlass", breakGlass(canonical != null ? canonical.getFrictionProfile() : null));
        // Dictionary 2.4: a request that is not delegated has no Delegation line (the v19 section says UNKNOWN).
        CanonicalSecurityContext.Delegation delegation = canonical != null ? canonical.getDelegation() : null;
        if (delegation != null && Boolean.TRUE.equals(delegation.getDelegated())) {
            // TO-2 (Q-84): the delegation unknowns without the instruction after them.
            values.value(FACTS, "Delegation", collapse(sections.buildDelegatedObjectiveContextSection(canonical),
                    Set.of(), ContextEvidenceGuidance::factsOf));
        }
        values.value(FACTS, "ThreatMatch",
                collapse(sections.buildThreatLearningSectionWithoutOutsideText(context.getBehaviorAnalysis())));
    }

    /**
     * The texts written outside the engine (W3-6): each once, in the dictionary order, with its source, quoted and cut
     * to the payload limit. They are never used for any normalisation, classification or comparison.
     */
    private static void untrustedText(SecurityDecisionPromptSections sections, SecurityPromptBuildContext context,
                                      CanonicalSecurityContext canonical, PromptEntryValues.Builder values) {
        int limit = sections.untrustedTextLimit();
        List<PromptListItem> items = new ArrayList<>();
        addUntrusted(items, UntrustedTextSources.DOCUMENT_DESCRIPTION,
                canonical != null && canonical.getResource() != null ? canonical.getResource().getAuthorText() : null, limit);
        // N-INJ-3: the target's business label is the host's free text (a document title, an export's description).
        addUntrusted(items, UntrustedTextSources.BUSINESS_LABEL,
                canonical != null && canonical.getResource() != null ? canonical.getResource().getBusinessLabel() : null,
                limit);
        addUntrusted(items, UntrustedTextSources.REQUEST_BODY, sections.decodedPayload(context.getEvent()), limit);
        for (String text : sections.outsideThreatKnowledgeTexts(context.getBehaviorAnalysis())) {
            addUntrusted(items, UntrustedTextSources.THREAT_KNOWLEDGE, text, limit);
        }
        addUntrusted(items, UntrustedTextSources.ANOMALY_SIGNAL_HEADER,
                canonical != null && canonical.getIntent() != null ? canonical.getIntent().getUntrustedAnomalySignalClaim() : null,
                limit);
        addUntrusted(items, UntrustedTextSources.ELEVATION_REASON,
                canonical != null && canonical.getRoleScopeProfile() != null
                        ? canonical.getRoleScopeProfile().getTemporaryElevationReason()
                        : null,
                limit);
        // N-INJ-1: the requester's own texts, in the plan's order (user agent, request path with its variables, the
        // session's earlier paths, tickets the requester names).
        LearningContextEvidence evidence = context.getLearningContextEvidence();
        addUntrusted(items, UntrustedTextSources.USER_AGENT, unparsedUserAgent(canonical != null ? canonical.getSession() : null,
                canonical != null ? canonical.getDevice() : null, evidence != null ? evidence.current() : null), limit);
        CanonicalSecurityContext.Resource resource = canonical != null ? canonical.getResource() : null;
        addUntrusted(items, UntrustedTextSources.REQUEST_PATH,
                firstText(resource != null ? resource.getRequestPath() : null, metadata(context.getEvent(), "requestPath")),
                limit);
        addUntrusted(items, UntrustedTextSources.SESSION_REQUEST_PATHS, sessionPaths(canonical), limit);
        for (String ticket : claimedTickets(canonical)) {
            addUntrusted(items, UntrustedTextSources.CLAIMED_TICKET, ticket, limit);
        }
        values.lines(UNTRUSTED, "UntrustedText{i}", items);
    }

    /** This request's target (the URL template's variables bound to the path), or null. */
    private static String currentTarget(CanonicalSecurityContext canonical) {
        return currentTarget(canonical != null ? canonical.getResource() : null);
    }

    /** The request's target as the baseline view names it (R1b-2: shared with the prompt inspector). */
    static String currentTarget(CanonicalSecurityContext.Resource resource) {
        return resource != null ? BaselineViewCalculator.target(resource.getPathFamily(), resource.getRequestPath()) : null;
    }

    /** The paths of the session's earlier requests in the order of the session's request list, or null. */
    private static String sessionPaths(CanonicalSecurityContext canonical) {
        return sessionPaths(canonical != null ? canonical.getSessionNarrativeProfile() : null);
    }

    /** The paths of the session's requests in the request list order, or null (R1b-2: shared with the inspector). */
    static String sessionPaths(CanonicalSecurityContext.SessionNarrativeProfile narrative) {
        if (narrative == null || narrative.getSessionDecisions() == null) {
            return null;
        }
        List<PromptListItem> paths = new ArrayList<>();
        for (SessionDecisionRecord decision : narrative.getSessionDecisions()) {
            if (decision != null && StringUtils.hasText(decision.path())) {
                paths.add(PromptListItem.ranked(decision.path(), decision.at() != null ? decision.at().toEpochMilli() : 0L));
            }
        }
        return paths.isEmpty() ? null : String.join("; ", PromptListOrder.TIME.sort(paths).stream().map(PromptListItem::text).toList());
    }

    /** The tickets the requester names in the request (the host checked them), as the requester wrote them. */
    private static List<String> claimedTickets(CanonicalSecurityContext canonical) {
        CanonicalSecurityContext.FrictionProfile friction = canonical != null ? canonical.getFrictionProfile() : null;
        if (friction == null || friction.getTicketRecords() == null) {
            return List.of();
        }
        return friction.getTicketRecords().stream()
                .filter(ticket -> ticket != null && Boolean.TRUE.equals(ticket.getClaimedByRequester())
                        && StringUtils.hasText(ticket.getTicketId()))
                .map(CanonicalSecurityContext.TicketRecord::getTicketId)
                .toList();
    }

    private static void addUntrusted(List<PromptListItem> items, String source, String text, int limit) {
        String value = PromptSlotRenderer.untrustedText(source, text, limit);
        if (value != null) {
            items.add(PromptListItem.named(value, source));
        }
    }

    private static void pastRecords(SecurityDecisionPromptSections sections, SecurityPromptBuildContext context,
                                    LearningContextEvidence evidence, PromptEntryValues.Builder values) {
        SecurityDecisionPromptSections.RagState rag = sections.ragState(context);
        values.value(PAST, "PastRecordsState", pastRecordsState(rag));
        String notRetrievedReason = notRetrievedReason(rag);
        boolean notRetrieved = notRetrievedReason != null;
        // W3-18: the counted facts of the exact lookup; without a lookup that counted them, their name is unknown now.
        String counts = sections.pastRecordCountsLine(context);
        if (counts != null) {
            values.value(PAST, "PastRecordCounts", counts);
        }
        else {
            values.unknown(PAST, "PastRecordCounts", PromptUnknownKind.UNAVAILABLE_NOW, countsUnknownReason(rag));
        }
        List<PromptListItem> records = sections.pastRecordItems(context);
        values.lines(PAST, "PastRecord{i}", records);
        if (records.stream().anyMatch(record -> !record.text().startsWith(PastRecordLines.TIME_NOT_RECORDED))) {
            values.clocked(PAST, "PastRecord{i}");
        }
        // Dictionary 1.4: the search exists but did not give the records this time (unavailable now).
        if (notRetrieved) {
            values.unknown(PAST, "PastRecord{i}", PromptUnknownKind.UNAVAILABLE_NOW, notRetrievedReason);
        }
        // W5-4 (Q-57 decision 4): the user's recent decisions that did not allow, facts only; without any the line
        // is left out.
        List<PromptListItem> denied = sections.pastDeniedItems(context);
        values.lines(PAST, "PastDeniedDecision{i}", denied);
        if (denied.stream().anyMatch(item -> !item.text().startsWith(PastRecordLines.TIME_NOT_RECORDED))) {
            values.clocked(PAST, "PastDeniedDecision{i}");
        }
        if (evidence != null && StringUtils.hasText(evidence.historicalComparableScope())) {
            values.headerQualifier(PAST, "scope " + evidence.historicalComparableScope());
        }
        values.value(PAST, "SupportingCases", supportingCases(evidence != null ? evidence.supportingComparableCount() : 0,
                sections.buildSupportingLearningContextSection(context.getBehaviorAnalysis())));
        // W3-5 (Q-61 X15, X26, X27): the summary and the pack summary restate the lines below them, and the
        // guardrails are instructions the system text holds.
        values.value(PAST, "ValidatedCases", collapse(sections.buildReasoningMemoryContextSection(
                context.getCanonicalSecurityContext()), REMOVED_MEMORY_LINES));
    }

    private static void unknown(CanonicalSecurityContext canonical, BaselineView view, PromptEntryValues.Builder values) {
        String coverage = coverageLine(canonical, view);
        if (coverage != null) {
            values.value(UNKNOWN, "Coverage", coverage);
        }
    }

    /**
     * The entries the render names unknown for want of a source, though the dictionary draws them with a missing text
     * without a value, as {@code BLOCK.Entry} keys: their missing text would claim a fact the context cannot give (P3
     * review 169). The challenge without a session, the session's requests without its decision history, the target
     * without a resource whose request path or business label names one, and without the decision facts' computation
     * the repeat with the differences (which have no missing text since N-DIC-1); without a context, all of them.
     * N-INS-2 (R1b): the render marks them by this rule and the inspector reads their UNKNOWN names by it on the
     * sealed context.
     */
    static List<String> withoutSource(CanonicalSecurityContext canonical) {
        List<String> keys = new ArrayList<>();
        CanonicalSecurityContext.SessionNarrativeProfile narrative =
                canonical != null ? canonical.getSessionNarrativeProfile() : null;
        if (canonical == null || canonical.getSession() == null) {
            keys.add(SESSION.name() + ".ChallengeVerified");
        }
        if (narrative == null || narrative.getSessionDecisions() == null) {
            keys.add(SESSION.name() + ".RequestsInSession");
        }
        if (target(canonical != null ? canonical.getResource() : null) == null) {
            keys.add(REQUEST.name() + ".Target");
        }
        if (canonical == null || canonical.getDecisionFacts() == null) {
            keys.add(FACTS.name() + ".DeviationsFromBaseline");
            keys.add(FACTS.name() + ".RepeatInSession");
        }
        return List.copyOf(keys);
    }

    /**
     * {@code context coverage PARTIAL; missing A; coverage warnings ...; bridge FULL; hints ...}: the sealed coverage
     * report's level, missing facts and warnings with the bridge's level and hints, or null without a report and a bridge
     * (R1b-7: shared with the inspector).
     */
    static String coverageLine(CanonicalSecurityContext canonical, BaselineView view) {
        ContextCoverageReport coverage = canonical != null ? canonical.getCoverage() : null;
        CanonicalSecurityContext.Bridge bridge = canonical != null ? canonical.getBridge() : null;
        if (coverage == null && bridge == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        if (coverage != null) {
            // W3-5 (Q-73 T2): the level, without the fixed sentence that restates it; a missing bridge context is
            // one of the missing facts (ContextCoverageEvaluator.appendBridgeFacts).
            parts.add(coverageLevel(coverage));
            String missing = missingFacts(coverage);
            if (missing != null) {
                parts.add(missing);
            }
            List<String> warnings = coverageWarnings(canonical, view);
            if (!warnings.isEmpty()) {
                parts.add("coverage warnings " + String.join("; ", warnings));
            }
        }
        parts.add(bridgeLevel(bridge));
        if (bridge != null && bridge.getRemediationHints() != null && !bridge.getRemediationHints().isEmpty()) {
            parts.add("hints " + String.join("; ", bridge.getRemediationHints()));
        }
        return String.join("; ", parts);
    }

    /** {@code context coverage PARTIAL}: the sealed coverage report's level (R1b-2: shared with the inspector). */
    static String coverageLevel(ContextCoverageReport coverage) {
        return "context coverage " + coverage.level();
    }

    /** {@code missing A, B}: the facts the coverage report misses, or null (R1b-2: shared with the inspector). */
    static String missingFacts(ContextCoverageReport coverage) {
        return coverage.missingCriticalFacts().isEmpty() ? null
                : "missing " + String.join(", ", coverage.missingCriticalFacts());
    }

    /** {@code bridge FULL}, or {@code bridge UNAVAILABLE} without a bridge or its level (R1b-2: shared). */
    static String bridgeLevel(CanonicalSecurityContext.Bridge bridge) {
        return "bridge " + (bridge != null ? firstText(bridge.getCoverageLevel(), "UNAVAILABLE") : "UNAVAILABLE");
    }

    // USER BASELINE

    /**
     * The baseline's Evidence line (dictionary 1.3): the fields first (collector, the window with its first and last
     * day, observations, the fallback and unknown shares the collector's field audits report, state, grade, scope), then
     * the grade's causes and every trust profile text as written before. Removing any of those texts is the decision of
     * the context removal list (Q-61), so W3-12 only puts the fields in front.
     */
    /**
     * The baseline state the evidence and status lines state (W3-19): the status line's state, computed from the
     * context the prompt is built from; null when the prompt has no status line.
     */
    static String baselineState(SecurityDecisionPromptSections sections, SecurityPromptBuildContext context) {
        LearningContextEvidence evidence = context.getLearningContextEvidence();
        return stateOf(baselineStatus(context.getBaselineStatus(), evidence != null ? evidence.personalBaseline() : null,
                evidence != null ? evidence.baselineView() : null, evidence, context.getCanonicalSecurityContext(),
                sections.pastRecordCounts(context)));
    }

    private static String stateOf(String status) {
        if (status == null || status.isBlank()) {
            return null;
        }
        int space = status.indexOf(' ');
        return space < 0 ? status : status.substring(0, space);
    }

    /** {@code window 7 days}: the view's window, before its first and last day (R1b-2: shared with the inspector). */
    static String evidenceWindow(BaselineView view) {
        return "window " + view.windowDays() + " days";
    }

    /** {@code observations 25 over 5 days} (R1b-2: shared with the inspector). */
    static String evidenceObservations(BaselineView view) {
        return "observations " + view.observations() + " over " + view.daysCovered() + " days";
    }

    /** {@code collector ROLE_SCOPE_PROFILE}: a trust profile's name (R1b-2: shared with the inspector). */
    static String collectorName(ContextTrustProfile trust) {
        return "collector " + firstText(trust.getProfileKey(), trust.getCollectorId(), "unnamed");
    }

    private static String baselineEvidence(CanonicalSecurityContext canonical, BaselineView view, Instant at,
                                           ZoneId zone) {
        List<String> segments = new ArrayList<>();
        List<String> parts = new ArrayList<>();
        if (view != null && view.observed()) {
            ContextTrustProfile personal = trustProfile(canonical, PERSONAL_WORK_PROFILE);
            List<String> fields = new ArrayList<>();
            fields.add("collector " + PERSONAL_WORK_PROFILE);
            fields.add(evidenceWindow(view) + windowDays(at, view.windowDays(), zone));
            fields.add(evidenceObservations(view));
            fields.add("fallback " + auditedShare(personal, ContextFieldTrustRecord::getFallbackRate));
            fields.add("unknown " + auditedShare(personal, ContextFieldTrustRecord::getUnknownRate));
            fields.add("evidence " + view.evidenceGrade().name());
            fields.add("scope personal");
            segments.add(String.join(", ", fields));
            if (!view.evidenceCauses().isEmpty()) {
                parts.add("causes " + String.join("; ", view.evidenceCauses()));
            }
        }
        if (canonical != null && canonical.getContextTrustProfiles() != null) {
            for (ContextTrustProfile trust : canonical.getContextTrustProfiles()) {
                if (trust == null) {
                    continue;
                }
                List<String> trustParts = new ArrayList<>();
                trustParts.add(collectorName(trust));
                if (StringUtils.hasText(trust.getProvenanceSummary())) {
                    trustParts.add("provenance " + trust.getProvenanceSummary().trim());
                }
                // TO-1 (Q-84): the limitations and warnings with their facts only, without the usage notes and the
                // instructions the collectors write with them.
                List<String> limits = factsOnly(trust.getScopeLimitations());
                if (!limits.isEmpty()) {
                    trustParts.add("limits " + String.join("; ", limits));
                }
                List<String> warnings = factsOnly(trust.getQualityWarnings());
                if (!warnings.isEmpty()) {
                    trustParts.add("warnings " + String.join("; ", warnings));
                }
                parts.add(String.join(", ", trustParts));
            }
        }
        if (!parts.isEmpty()) {
            segments.add(String.join(", ", parts));
        }
        return segments.isEmpty() ? null : String.join("; ", segments);
    }

    private static final String PERSONAL_WORK_PROFILE = "PERSONAL_WORK_PROFILE";

    /** The texts with their facts only ({@link ContextEvidenceGuidance}); a text of instructions only is left out. */
    private static List<String> factsOnly(List<String> texts) {
        if (texts == null) {
            return List.of();
        }
        return texts.stream().map(ContextEvidenceGuidance::factsOf).filter(Objects::nonNull).toList();
    }

    /** The reasoning memory lines the user removed (W3-5, Q-61 X15, X26, X27). */
    private static final Set<String> REMOVED_MEMORY_LINES =
            Set.of("ReasoningMemorySummary", "MemoryGuardrails", "CrossTenantObjectiveMisusePackSummary");

    private static ContextTrustProfile trustProfile(CanonicalSecurityContext canonical, String key) {
        if (canonical == null || canonical.getContextTrustProfiles() == null) {
            return null;
        }
        return canonical.getContextTrustProfiles().stream()
                .filter(trust -> trust != null && key.equals(trust.getProfileKey()))
                .findFirst().orElse(null);
    }

    /**
     * {@code  (09-23..09-29)}: the event clock days the window runs over. The view reads the observations of the window
     * that ends at the request (BaselineViewCalculator.window); nothing without the request time.
     */
    private static String windowDays(Instant at, int days, ZoneId zone) {
        if (at == null || days <= 0) {
            return "";
        }
        LocalDateTime from = LocalDateTime.ofInstant(at.minus(Duration.ofDays(days)), zone);
        LocalDateTime to = LocalDateTime.ofInstant(at, zone);
        return String.format(Locale.ROOT, " (%02d-%02d..%02d-%02d)", from.getMonthValue(), from.getDayOfMonth(),
                to.getMonthValue(), to.getDayOfMonth());
    }

    /** The highest share the collector's field audits report, in percent; {@code not audited} without any audit. */
    private static String auditedShare(ContextTrustProfile trust, Function<ContextFieldTrustRecord, Double> rate) {
        Double highest = null;
        if (trust != null && trust.getFieldRecords() != null) {
            for (ContextFieldTrustRecord record : trust.getFieldRecords()) {
                Double value = record != null ? rate.apply(record) : null;
                if (value != null && (highest == null || value > highest)) {
                    highest = value;
                }
            }
        }
        return highest == null ? "not audited" : Math.round(highest * 100) + "%";
    }

    /**
     * The usual actions with their counts; an action family the view inferred says so at the counts it made (dictionary
     * 1.3, S-21), with the cause as the view states it.
     */
    private static String usualActions(BaselineView view) {
        String counts = counted(view.actionCounts());
        if (counts == null || view.evidenceGrade() == BaselineView.EvidenceGrade.STRONG) {
            return counts;
        }
        List<String> inferred = view.evidenceCauses().stream()
                .filter(cause -> cause.startsWith("action family inferred from "))
                .toList();
        return inferred.isEmpty() ? counts
                : counts + " (evidence " + view.evidenceGrade().name() + ": " + String.join("; ", inferred) + ")";
    }

    /** {@code source host (SECURITY_CONTEXT)}: the grade of a host fact and the bridge source it came through. */
    private static String hostSource(String source) {
        return "source host" + (StringUtils.hasText(source) ? " (" + source.trim() + ")" : "");
    }

    /**
     * The coverage warnings of the request's context (W3-8). They are about the whole context of this request, so they
     * are written with the facts not known now and not in the baseline block, which changes only with the baseline
     * (dictionary 1.1). What the trust profiles state is left out, so each warning is written once (the v19
     * missing-knowledge section does the same).
     */
    private static List<String> coverageWarnings(CanonicalSecurityContext canonical, BaselineView view) {
        ContextCoverageReport coverage = canonical != null ? canonical.getCoverage() : null;
        if (coverage == null) {
            return List.of();
        }
        Set<String> stated = new HashSet<>();
        if (canonical.getContextTrustProfiles() != null) {
            for (ContextTrustProfile trust : canonical.getContextTrustProfiles()) {
                if (trust == null) {
                    continue;
                }
                stated.add(ContextSemanticBoundaryPolicy.evidenceCautionStatement(trust, view));
                if (trust.getScopeLimitations() != null) {
                    trust.getScopeLimitations().forEach(limitation -> stated.add("Scope limitation: " + limitation));
                }
                if (trust.getQualityWarnings() != null) {
                    stated.addAll(trust.getQualityWarnings());
                }
            }
        }
        // TO-3 (Q-85): each warning with its fact only; the v20 system text states the evidence rules its clause repeats.
        return coverage.confidenceWarnings().stream()
                .filter(warning -> !stated.contains(warning))
                .map(ContextEvidenceGuidance::factsOf)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    /**
     * The personal baseline state and why. A history the core calls sparse is no personal baseline (NONE) when nothing
     * personal is known: no learned requests, no observations and no personal past records (N-MISS-1 D1). An
     * organization baseline is not the user's history. A sparse history says what it has.
     */
    private static String baselineStatus(BaselineStatus status, BaselineEvidenceSnapshot personal, BaselineView view,
                                         LearningContextEvidence evidence, CanonicalSecurityContext canonical,
                                         PastRecordCounts counts) {
        if (status == null) {
            return null;
        }
        String name = status.name();
        List<String> details = new ArrayList<>();
        Long learned = personal != null ? personal.updateCount() : null;
        if (status == BaselineStatus.SPARSE_PERSONAL_HISTORY) {
            int observations = view != null ? view.observations() : 0;
            // W3-19: the past records the exact lookup counted, not only the ones it read up to its limit.
            int personalRecords = counts != null ? (int) Math.min(Integer.MAX_VALUE, counts.total())
                    : evidence != null ? evidence.personalRetrievedEvidence().size() : 0;
            if ((learned == null || learned == 0L) && observations == 0 && personalRecords == 0) {
                name = BaselineLineValues.NONE;
                details.add("no learned requests");
                details.add("no observations");
            }
            else {
                if (learned != null) {
                    details.add(learned + " learned requests");
                }
                // Q-79 A3: the number the exact lookup counted is PastRecordCounts's; without that count, the number read
                // is said here, where no other line states it.
                if (counts == null && personalRecords > 0) {
                    details.add(personalRecords + (personalRecords == 1 ? " personal past record" : " personal past records"));
                }
                if (observations > 0) {
                    details.add(observations + (observations == 1 ? " observation" : " observations"));
                }
            }
        }
        else if (learned != null) {
            details.add(learned + " learned requests");
        }
        Boolean newUser = canonical != null && canonical.getSession() != null ? canonical.getSession().getNewUser() : null;
        if (newUser != null) {
            details.add(newUser ? "account flagged new" : "account not new");
        }
        if (personal != null && personal.status() != null) {
            details.add("personal baseline " + personal.status().name());
        }
        // W5-10 D4: a personal baseline learned but not established says which conditions it misses.
        if (personal != null && personal.status() == BaselineEvidenceStatus.AVAILABLE && !personal.established()
                && StringUtils.hasText(personal.diagnostic())) {
            details.add("not established: " + personal.diagnostic());
        }
        // W5-7 D4: the window's observations a value of an earlier vocabulary keeps out of the comparison.
        int notComparable = view != null && view.counts() != null ? view.counts().vocabularyNotComparable() : 0;
        if (notComparable > 0) {
            details.add("vocabulary migration: " + notComparable
                    + (notComparable == 1 ? " observation" : " observations") + " not comparable");
        }
        return name + (details.isEmpty() ? "" : " (" + String.join(", ", details) + ")");
    }

    /**
     * The USER BASELINE values an observed baseline view gives on its own, by entry name (a value the view does not hold
     * is left out). The render and the prompt inspector read the same function: the inspector compares the drawn lines
     * with the sealed view through it.
     */
    static Map<String, String> viewLines(BaselineView view) {
        Map<String, String> lines = new LinkedHashMap<>();
        lines.put("UsualHours", usualHours(view));
        lines.put("UsualDays", usualDays(view));
        lines.put("UsualTargets", names(view.usualTargets()));
        lines.put("UsualActions", usualActions(view));
        lines.put("UsualResourceClass", counted(classCounts(view.resourceClasses())));
        if (view.exportSize() != null) {
            lines.put("UsualExportSize", "up to " + number(view.exportSize().largestItems())
                    + " items per export (median " + number(view.exportSize().medianItems()) + ", "
                    + view.exportSize().exports() + " exports)");
        }
        BaselineView.Rate rate = view.counts() != null ? view.counts().rate() : null;
        if (rate != null) {
            // W5-10 D5, N-RATE-1: the definition the decision facts compare the request's rate with: each request's
            // count of the 60 minutes up to it, with how many requests were counted. A view without a usual rate of
            // this definition draws no line, so the dictionary's missing notation stands; the mean of the active clock
            // hours (requestsPerActiveHour) is another definition and is not drawn beside the request's rate.
            lines.put("UsualRequestRate", "median " + rate.median() + ", 95th percentile " + rate.p95() + " requests "
                    + BaselineView.Rate.WINDOW + " (" + rate.requests()
                    + (rate.requests() == 1 ? " request)" : " requests)"));
        }
        if (view.usualSessionMinutes() != null) {
            lines.put("UsualSessionLength", view.usualSessionMinutes() + " min");
        }
        lines.put("UsualPrivilegedActions", view.privilegedActions() + " of " + view.observations() + " observations");
        lines.put("KnownRareTasks", names(view.knownRareTasks(), "; "));
        lines.values().removeIf(Objects::isNull);
        return lines;
    }

    private static String usualHours(BaselineView view) {
        String usual = ranges(view.usualHours(), hour -> String.format(Locale.ROOT, "%02d", hour));
        String seen = String.join(",", view.seenHours().stream().map(String::valueOf).toList());
        if (!StringUtils.hasText(usual)) {
            return seen.isEmpty() ? null : "seen " + seen;
        }
        return usual + (seen.isEmpty() ? "" : " (seen " + seen + ")");
    }

    /** Day numbers (1 Monday to 7 Sunday) as the day name ranges UsualDays uses; values that are not days stay. */
    private static String dayNames(List<String> days) {
        List<Integer> numbers = new ArrayList<>();
        for (String day : days) {
            try {
                numbers.add(Integer.parseInt(day.trim()));
            }
            catch (RuntimeException notADay) {
                return String.join(",", days);
            }
        }
        IntFunction<String> name = day -> day >= 1 && day <= 7
                ? DayOfWeek.of(day).getDisplayName(TextStyle.SHORT, Locale.ROOT) : String.valueOf(day);
        return ranges(numbers.stream().sorted().distinct().toList(), name);
    }

    private static String usualDays(BaselineView view) {
        IntFunction<String> name = day -> day >= 1 && day <= 7
                ? DayOfWeek.of(day).getDisplayName(TextStyle.SHORT, Locale.ROOT) : String.valueOf(day);
        String usual = ranges(view.usualDays(), name);
        String seen = ranges(view.seenDays(), name);
        if (!StringUtils.hasText(usual)) {
            return StringUtils.hasText(seen) ? "seen " + seen : null;
        }
        return usual + (StringUtils.hasText(seen) && !seen.equals(usual) ? " (seen " + seen + ")" : "");
    }

    private static String usualDevices(BaselineView view, BaselineEvidenceSnapshot personal) {
        if (view != null && !view.usualDevices().isEmpty()) {
            return names(view.usualDevices());
        }
        List<String> browsers = view != null && !view.usualBrowsers().isEmpty() ? view.usualBrowsers()
                : personal != null && personal.browsers() != null ? personal.browsers() : List.of();
        List<String> systems = view != null && !view.usualOperatingSystems().isEmpty() ? view.usualOperatingSystems()
                : personal != null && personal.operatingSystems() != null ? personal.operatingSystems() : List.of();
        List<String> parts = new ArrayList<>();
        if (!browsers.isEmpty()) {
            parts.add("browsers " + names(browsers));
        }
        if (!systems.isEmpty()) {
            parts.add("systems " + names(systems));
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    private static List<String> personalNetworks(BaselineEvidenceSnapshot personal) {
        if (personal == null || personal.networks() == null) {
            return List.of();
        }
        List<String> networks = new ArrayList<>();
        for (String network : personal.networks()) {
            String band = SecuritySemanticNormalizer.normalizeNetwork(null, network);
            if (StringUtils.hasText(band) && !networks.contains(band)) {
                networks.add(band);
            }
        }
        return networks;
    }

    private static List<String> personalLoginMethods(BaselineEvidenceSnapshot personal) {
        if (personal == null || personal.authenticationTypes() == null) {
            return List.of();
        }
        List<String> methods = new ArrayList<>();
        for (String method : personal.authenticationTypes()) {
            String normalized = SecuritySemanticNormalizer.normalizeAuthenticationType(method);
            if (StringUtils.hasText(normalized) && !methods.contains(normalized)) {
                methods.add(normalized);
            }
        }
        return methods;
    }

    /** {@code 25 protected requests in the last 7 days; protectable share 0.40} (R1b-2: shared with the inspector). */
    static String workProfile(CanonicalSecurityContext.WorkProfile workProfile, BaselineView view) {
        String value = view.observations() + " protected requests in the last " + view.windowDays() + " days";
        if (workProfile != null && workProfile.getProtectableInvocationDensity() != null) {
            value += "; protectable share " + String.format(Locale.ROOT, "%.2f", workProfile.getProtectableInvocationDensity());
        }
        return value;
    }

    private static String peerReference(SecurityDecisionPromptSections sections, SecurityPromptBuildContext context,
                                        LearningContextEvidence evidence) {
        List<String> parts = new ArrayList<>();
        BaselineEvidenceSnapshot supporting = evidence != null ? evidence.supportingBaseline() : null;
        if (supporting != null && supporting.available()) {
            // Dictionary 2.1 order: the cohort and its usual time, the status with its sample, then its own summary
            // (kept as written until the removal decision, Q-61). The days use the day names of UsualDays.
            List<String> usual = new ArrayList<>();
            // W5-10 D7: with the organization's counts, each usual value with the share of its learned requests.
            if (supporting.accessHours() != null && !supporting.accessHours().isEmpty()) {
                String shared = shares(supporting, "hour:", supporting.accessHours(), Function.identity());
                usual.add("hours " + (shared != null ? shared : String.join(",", supporting.accessHours())));
            }
            if (supporting.accessDays() != null && !supporting.accessDays().isEmpty()) {
                String shared = shares(supporting, "day:", supporting.accessDays(), day -> dayNames(List.of(day)));
                usual.add("days " + (shared != null ? shared : dayNames(supporting.accessDays())));
            }
            String cohort = "cohort organization" + (usual.isEmpty() ? "" : ": " + String.join(", ", usual));
            String status = "status " + (supporting.status() != null ? supporting.status().name() : "AVAILABLE")
                    + (supporting.updateCount() != null ? " (" + supporting.updateCount() + " updates)" : "");
            parts.add(cohort);
            parts.add(status);
            if (StringUtils.hasText(supporting.summary())) {
                parts.add("summary " + supporting.summary().trim());
            }
        }
        // W3-5 (Q-61 X48): the seed policy restates the weight state of the runtime weight line and the cohort figures.
        // TO-2 (Q-84): the seed's facts without its instruction sentences.
        String seed = collapse(sections.buildCohortBaselineSeedSection(context.getBehaviorAnalysis()),
                Set.of("Seed policy"), ContextEvidenceGuidance::factsOf);
        if (seed != null) {
            parts.add(seed);
        }
        return parts.isEmpty() ? null : String.join("; ", parts) + "; reference only";
    }

    /** {@code 9:48%,10:50%}: each value with its share, null when the baseline carries no counts of the dimension. */
    private static String shares(BaselineEvidenceSnapshot baseline, String prefix, List<String> values,
                                 Function<String, String> name) {
        List<String> parts = new ArrayList<>();
        for (String value : values) {
            Integer share = baseline.sharePercent(prefix, value);
            if (share == null) {
                return null;
            }
            parts.add(name.apply(value) + ":" + share + "%");
        }
        return String.join(",", parts);
    }

    // SESSION

    private static String loginMethod(SecurityPromptBuildContext context, CanonicalSecurityContext canonical,
                                      CanonicalSecurityContext.Session session, Instant at) {
        SecurityEvent event = context.getEvent();
        String raw = firstText(metadata(event, "authMethod"),
                context.getSessionContext() != null ? context.getSessionContext().getAuthMethod() : null);
        String typed = session != null ? session.getAuthenticationType() : null;
        String method = firstText(raw, typed);
        if (method == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        parts.add(loginMethodHead(method, typed, session != null ? session.getAuthenticationAssurance() : null));
        Instant authenticated = session != null ? parseInstant(session.getAuthenticationTime()) : null;
        if (authenticated != null && at != null) {
            parts.add(RelativeTime.of(authenticated, at));
        }
        String mfa = mfaState(session != null ? session.getMfaVerified() : null);
        if (mfa != null) {
            parts.add(mfa);
        }
        Instant lastMfa = session != null ? parseInstant(session.getLastMfaUsedAt()) : null;
        if (lastMfa != null && at != null) {
            parts.add("last MFA " + RelativeTime.of(lastMfa, at));
        }
        String source = canonical != null && canonical.getBridge() != null
                ? canonical.getBridge().getAuthenticationSource() : null;
        return String.join(", ", parts) + "; " + hostSource(source);
    }

    /** {@code 42 min since login}: the session's age and what it counts from (R1b-2: shared with the inspector). */
    static String sessionAge(int minutes, String basis) {
        return minutes + " min since " + sessionStart(basis);
    }

    /** {@code at 14:23 (1 min before this request)} on the event clock (R1b-2: shared with the inspector). */
    static String challengeVerified(Instant verified, Instant at, ZoneId zone) {
        return "at " + clock(verified, zone) + relative(verified, at);
    }

    /** {@code MFA completed in another session 2 h before this request}; null without both times (R1b-2: shared). */
    static String mfaElsewhere(Instant elsewhere, Instant at) {
        return elsewhere != null && at != null ? "MFA completed in another session " + RelativeTime.of(elsewhere, at) : null;
    }

    /**
     * {@code 3 in last 5 min}, or the count with the window not stated (dictionary 2.2: a count states the window it was
     * counted in); null without a count (R1b-2: shared).
     */
    static String failedLogins(CanonicalSecurityContext.Session session) {
        if (session == null || session.getFailedLoginAttempts() == null) {
            return null;
        }
        return session.getFailedLoginWindowMinutes() != null
                ? session.getFailedLoginAttempts() + " in last " + session.getFailedLoginWindowMinutes() + " min"
                : session.getFailedLoginAttempts() + " recent failed logins (window not stated)";
    }

    static String mfaFailures(CanonicalSecurityContext.Session session) {
        return session != null && session.getRecentMfaFailureCount() != null
                ? session.getRecentMfaFailureCount() + " recent MFA failures (window not stated)" : null;
    }

    /**
     * {@code 14 requests in last 60 min (0.23 per min); host count 17, window not stated} (W5-10 D5): the engine's count
     * of the user's decisions in the last 60 minutes, and the host's count, which states no window.
     */
    static String recentRequests(CanonicalSecurityContext.Session session,
                                 CanonicalSecurityContext.SessionNarrativeProfile narrative) {
        List<String> parts = new ArrayList<>();
        Integer counted = narrative != null ? narrative.getUserRequestsLastHour() : null;
        if (counted != null) {
            parts.add(counted + " requests in last 60 min ("
                    + String.format(Locale.ROOT, "%.2f", counted / 60.0) + " per min)");
        }
        if (session != null && session.getRecentRequestCount() != null) {
            parts.add("host count " + session.getRecentRequestCount() + ", window not stated");
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    static String concurrentSessions(CanonicalSecurityContext.Session session) {
        return session != null && session.getConcurrentSessions() != null
                ? session.getConcurrentSessions() + " concurrent sessions" : null;
    }

    static String passwordAge(CanonicalSecurityContext.Session session) {
        return session != null && session.getPasswordAgeDays() != null
                ? session.getPasswordAgeDays() + " days since the password changed" : null;
    }

    static String recentSensitiveAccess(CanonicalSecurityContext.ObservedScope scope) {
        return scope != null && scope.getRecentSensitiveAccessCount() != null
                ? scope.getRecentSensitiveAccessCount() + " recent sensitive accesses" : null;
    }

    /** {@code MFA verified} or {@code MFA not verified}; null when the session does not say (R1b-2: shared). */
    static String mfaState(Boolean verified) {
        return verified == null ? null : verified ? "MFA verified" : "MFA not verified";
    }

    private static String sessionStart(String basis) {
        if (basis == null) {
            return "session start";
        }
        return switch (basis.trim().toUpperCase(Locale.ROOT)) {
            case "LOGIN" -> "login";
            case "SESSION_CREATED" -> "session start";
            case "FIRST_ANALYSED_REQUEST" -> "the first analysed request";
            default -> basis.trim();
        };
    }

    static String requestsInSession(List<SessionDecisionRecord> decisions, String currentTarget, Instant at,
                                    ZoneId zone) {
        List<PromptListItem> items = new ArrayList<>();
        for (SessionDecisionRecord decision : decisions) {
            if (decision == null) {
                continue;
            }
            List<String> parts = new ArrayList<>();
            if (decision.at() != null) {
                parts.add(clock(decision.at(), zone) + relative(decision.at(), at));
            }
            parts.add(firstText(decision.actionFamily(), decision.method(), "request"));
            // The paths and their values are the requester's text, drawn as an untrusted text (N-INJ-1): the item says
            // whether the request had this request's target.
            if (decision.target() != null) {
                parts.add(decision.target().equals(currentTarget) ? "this target" : "another target");
            }
            if (decision.items() != null) {
                parts.add(number(decision.items()) + " items");
            }
            String text = String.join(" ", parts) + " -> " + firstText(decision.outcome(), "UNKNOWN");
            items.add(PromptListItem.ranked(text, decision.at() != null ? decision.at().toEpochMilli() : 0L));
        }
        if (items.isEmpty()) {
            return null;
        }
        List<String> texts = PromptListOrder.TIME.sort(items).stream().map(PromptListItem::text).toList();
        return texts.size() + " so far: " + String.join("; ", texts);
    }

    static String recentDenied(List<SessionDecisionRecord> decisions,
                               CanonicalSecurityContext.ObservedScope scope, ZoneId zone) {
        List<String> parts = new ArrayList<>();
        if (decisions != null) {
            List<PromptListItem> denied = new ArrayList<>();
            for (SessionDecisionRecord decision : decisions) {
                if (decision != null && SessionDecisionRecord.AUTHORIZATION_DENIED.equals(decision.outcome())) {
                    String at = decision.at() != null ? clock(decision.at(), zone) + " " : "";
                    // Without a method the item names the time and the target only (P3-EXTRA-13).
                    String method = firstText(decision.method());
                    denied.add(PromptListItem.ranked(at + (method != null ? method + " " : "")
                                    + firstText(decision.target(), decision.path(), "unknown target"),
                            decision.at() != null ? decision.at().toEpochMilli() : 0L));
                }
            }
            if (!denied.isEmpty()) {
                parts.add(denied.size() + " denied in this session ("
                        + String.join("; ", PromptListOrder.TIME.sort(denied).stream().map(PromptListItem::text).toList()) + ")");
            }
        }
        if (scope != null && scope.getRecentDeniedAccessCount() != null && scope.getRecentDeniedAccessCount() > 0) {
            parts.add(scope.getRecentDeniedAccessCount() + " recent denied accesses (host count)");
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    /** {@code PASSWORD (TOKEN) (assurance HIGH)}: the login method, the session's type when it differs, the assurance. */
    static String loginMethodHead(String method, String typed, String assurance) {
        // The session's type is trimmed; blank or equal to the method, it adds nothing (P3-EXTRA-34).
        String type = firstText(typed);
        String head = method + (type != null && !type.equalsIgnoreCase(method) ? " (" + type + ")" : "");
        if (StringUtils.hasText(assurance)) {
            head += " (assurance " + assurance.trim() + ")";
        }
        return head;
    }

    // REQUEST

    /** {@code Wed 03:17}: the request's day and time on the event clock (R1b-2: shared with the inspector). */
    static String requestClock(Instant at, ZoneId zone) {
        LocalDateTime local = LocalDateTime.ofInstant(at, zone);
        return local.getDayOfWeek().getDisplayName(TextStyle.SHORT, Locale.ROOT) + " "
                + String.format(Locale.ROOT, "%02d:%02d", local.getHour(), local.getMinute());
    }

    /** {@code 4,831 items}, or null without a requested size (R1b-2: shared with the inspector). */
    static String requestedSize(Integer items) {
        return items != null ? number(items) + " items" : null;
    }

    private static String subject(SecurityPromptBuildContext context, CanonicalSecurityContext canonical, Instant at) {
        CanonicalSecurityContext.Actor actor = canonical != null ? canonical.getActor() : null;
        return subjectLine(firstText(actor != null ? actor.getUserId() : null, context.getUserId()), accountAge(actor, at),
                canonical);
    }

    /**
     * {@code alice (HUMAN_USER, account 120 days, dept ...)}: the user with the sealed subject's type, the account part
     * and the sealed actor's details, or null without a user (R1b-7: shared with the inspector).
     */
    static String subjectLine(String userId, String account, CanonicalSecurityContext canonical) {
        if (userId == null) {
            return null;
        }
        CanonicalSecurityContext.Actor actor = canonical != null ? canonical.getActor() : null;
        List<String> parts = new ArrayList<>();
        ExecutionSubject subject = canonical != null ? canonical.getExecutionSubject() : null;
        if (subject != null && StringUtils.hasText(subject.subjectType())) {
            parts.add(subject.subjectType());
        }
        parts.add(account);
        if (actor != null) {
            addPart(parts, "dept ", actor.getDepartment());
            addPart(parts, "position ", actor.getPosition());
            addPart(parts, "tenant ", actor.getTenantId());
            if (StringUtils.hasText(actor.getOrganizationId())
                    && !actor.getOrganizationId().equals(actor.getTenantId())) {
                parts.add("organization " + actor.getOrganizationId().trim());
            }
            addPart(parts, "external subject ", actor.getExternalSubjectId());
            addPart(parts, "bridge subject ", actor.getBridgeSubjectKey());
        }
        return userId + " (" + String.join(", ", parts) + ")";
    }

    /** {@code account 120 days} to the request time, or {@code account age not known} (R1b-7: shared with the inspector). */
    static String accountAge(CanonicalSecurityContext.Actor actor, Instant at) {
        Instant created = actor != null ? parseInstant(actor.getAccountCreatedAt()) : null;
        return created != null && at != null
                ? "account " + Math.max(0L, Duration.between(created, at).toDays()) + " days"
                : "account age not known";
    }

    /** Whether the actor's account creation time reads, so that the account part needs the request time (R1b-7). */
    static boolean accountCreatedKnown(CanonicalSecurityContext.Actor actor) {
        return actor != null && parseInstant(actor.getAccountCreatedAt()) != null;
    }

    /**
     * {@code ROLE_A, ROLE_B; scope tags ...; privileged flow; source host (X)}: the sealed roles with the authorization's
     * scope tags and flow and the host source, or null without roles (R1b-7: shared with the inspector).
     */
    static String rolesLine(CanonicalSecurityContext canonical) {
        CanonicalSecurityContext.Authorization authorization = canonical != null ? canonical.getAuthorization() : null;
        CanonicalSecurityContext.Actor actor = canonical != null ? canonical.getActor() : null;
        List<String> roles = authorization != null && !authorization.getEffectiveRoles().isEmpty()
                ? authorization.getEffectiveRoles()
                : actor != null ? actor.getRoleSet() : List.of();
        String value = names(roles);
        if (value == null) {
            return null;
        }
        if (authorization != null && !authorization.getScopeTags().isEmpty()) {
            value += "; scope tags " + names(authorization.getScopeTags());
        }
        if (authorization != null && Boolean.TRUE.equals(authorization.getPrivileged())) {
            value += "; privileged flow";
        }
        return withSource(value, authorizationSource(canonical));
    }

    /**
     * {@code document:export, document:read; source host (X)}: the sealed permissions with the host source, or null
     * without permissions (R1b-7: shared with the inspector).
     */
    static String permissionsLine(CanonicalSecurityContext canonical) {
        CanonicalSecurityContext.Authorization authorization = canonical != null ? canonical.getAuthorization() : null;
        CanonicalSecurityContext.Actor actor = canonical != null ? canonical.getActor() : null;
        return withSource(names(authorization != null && !authorization.getEffectivePermissions().isEmpty()
                ? authorization.getEffectivePermissions()
                : actor != null ? actor.getAuthoritySet() : List.of()), authorizationSource(canonical));
    }

    /** The host source the bridge names for the authorization, or null. */
    private static String authorizationSource(CanonicalSecurityContext canonical) {
        return canonical != null && canonical.getBridge() != null ? canonical.getBridge().getAuthorizationSource() : null;
    }

    private static String withSource(String value, String source) {
        if (value == null) {
            return null;
        }
        return value + "; " + hostSource(source);
    }

    private static String action(SecurityEvent event, CanonicalSecurityContext.Resource resource,
                                 CurrentLearningContextSnapshot current) {
        return actionLine(firstText(resource != null ? resource.getActionFamily() : null,
                        current != null ? current.actionFamily() : null),
                resource != null ? resource.getActionFamilySource() : null,
                firstText(resource != null ? resource.getHttpMethod() : null, metadata(event, "httpMethod")),
                firstText(resource != null ? resource.getRequestPath() : null, metadata(event, "requestPath")),
                firstText(resource != null ? resource.getPathFamily() : null, current != null ? current.pathFamily() : null),
                protectedMethod(firstText(metadata(event, "protectableMethod"), qualifiedResourceMethod(resource))));
    }

    /**
     * {@code EXPORT (declared) POST (template /a/{b}, method Type.call)}: the family with its source, the method, the path
     * template and the protected method, or null without a family, a method and a path (R1b-7: shared with the
     * inspector). The request path is the requester's text: it is drawn once, as an untrusted text (N-INJ-1).
     */
    static String actionLine(String family, String familySource, String method, String path, String template,
                             String protectedMethod) {
        if (family == null && method == null && path == null) {
            return null;
        }
        StringBuilder value = new StringBuilder(firstText(family, "UNKNOWN"));
        value.append(" (").append(actionSource(familySource)).append(')');
        if (method != null) {
            value.append(' ').append(method);
        }
        List<String> details = new ArrayList<>();
        if (template != null) {
            details.add("template " + template);
        }
        if (protectedMethod != null) {
            details.add("method " + protectedMethod);
        }
        if (!details.isEmpty()) {
            value.append(" (").append(String.join(", ", details)).append(')');
        }
        return value.toString();
    }

    private static String actionSource(String source) {
        if (!StringUtils.hasText(source)) {
            return "source not stated";
        }
        String trimmed = source.trim();
        int separator = trimmed.indexOf(':');
        String grade = separator < 0 ? trimmed : trimmed.substring(0, separator);
        String key = separator < 0 ? "" : trimmed.substring(separator + 1);
        if ("host".equalsIgnoreCase(grade)) {
            return "declared";
        }
        String from = switch (key) {
            case "protectableMethod", "method" -> "method name";
            case "protectableResourceUrl" -> "resource URL";
            case "resourceUrlTemplate" -> "URL template";
            case "httpMethod" -> "HTTP method";
            default -> key;
        };
        return from.isEmpty() ? grade : grade + " from " + from;
    }

    /** The resource id when it names a method ({@code a.b.Type#method}), or null (R1b-7: shared with the inspector). */
    static String qualifiedResourceMethod(CanonicalSecurityContext.Resource resource) {
        return resource != null && resource.getResourceId() != null && resource.getResourceId().contains("#")
                ? resource.getResourceId() : null;
    }

    /**
     * {@code Type.method} of a qualified method ({@code a.b.Type#method} or {@code a.b.Type.method}), or null (R1b-7:
     * shared with the inspector).
     */
    static String protectedMethod(String qualified) {
        if (qualified == null) {
            return null;
        }
        String method = qualified.contains("#") ? qualified.substring(qualified.indexOf('#') + 1) : null;
        String type = qualified.contains("#") ? qualified.substring(0, qualified.indexOf('#')) : qualified;
        int dot = type.lastIndexOf('.');
        if (method == null && dot > 0) {
            int previous = type.lastIndexOf('.', dot - 1);
            return type.substring(previous + 1);
        }
        String simple = dot >= 0 ? type.substring(dot + 1) : type;
        return method == null ? simple : simple + "." + method;
    }

    private static String target(CanonicalSecurityContext.Resource resource) {
        if (resource == null) {
            return null;
        }
        String binding = BaselineViewCalculator.target(resource.getPathFamily(), resource.getRequestPath());
        String label = targetLabel(resource);
        String category = StringUtils.hasText(resource.getResourceCategory()) ? resource.getResourceCategory().trim() : null;
        if (binding == null && label == null) {
            return null;
        }
        StringBuilder value = new StringBuilder(targetHead(resource));
        if (label != null) {
            value.append(" (").append(label).append(')');
        }
        if (category != null) {
            value.append(", category ").append(category);
        }
        return value.toString();
    }

    /**
     * Where the target's business label is ({@code business label in UNTRUSTED TEXT}), or null without a label. The
     * label is the host's free text (a document title, an export's description): it is drawn once, as an untrusted
     * text (N-INJ-3). R1b-2: shared with the inspector.
     */
    static String targetLabel(CanonicalSecurityContext.Resource resource) {
        return resource != null && StringUtils.hasText(resource.getBusinessLabel()) ? TARGET_LABEL_NOTE : null;
    }

    /**
     * The target's name: the path template's variables when the request path binds them, else {@code resource}. The
     * variables' values are the requester's text (in the request path): the line names the variables (N-INJ-1). R1b-2:
     * shared with the inspector.
     */
    static String targetHead(CanonicalSecurityContext.Resource resource) {
        return BaselineViewCalculator.target(resource.getPathFamily(), resource.getRequestPath()) != null
                ? BaselineViewCalculator.variables(resource.getPathFamily()) + " from the request path" : "resource";
    }

    /**
     * {@code CRITICAL (sensitivity CRITICAL, sensitive-resource flag, ...)}: the sealed resource's class with its
     * sensitivity and flags, or null without a class (R1b-7: shared with the inspector).
     */
    static String resourceClass(CanonicalSecurityContext.Resource resource) {
        if (resource == null || !StringUtils.hasText(resource.getResourceClass())) {
            return null;
        }
        List<String> details = new ArrayList<>();
        addPart(details, "sensitivity ", resource.getSensitivity());
        if (Boolean.TRUE.equals(resource.getSensitiveResource())) {
            details.add("sensitive-resource flag");
        }
        if (Boolean.TRUE.equals(resource.getExportSensitive())) {
            details.add("export-sensitive");
        }
        if (Boolean.TRUE.equals(resource.getPrivileged())) {
            details.add("privileged");
        }
        // W3-5 (Q-73 T1): the prompt-quality verification mark is an operations gate, not a fact for the decision.
        return resource.getResourceClass().trim() + (details.isEmpty() ? "" : " (" + String.join(", ", details) + ")");
    }

    private static String network(CanonicalSecurityContext.Session session, CanonicalSecurityContext.Location location,
                                  CurrentLearningContextSnapshot current) {
        return networkLine(session, firstText(current != null ? current.network() : null,
                location != null ? location.getIpBand() : null), location);
    }

    /**
     * {@code 10.40.12.7 (10.40.12.0/24, zone CORPORATE, Seoul, KR, ASN AS1)}: the sealed client address with the band
     * and the sealed location, or null without an address and a band (R1b-7: shared with the inspector).
     */
    static String networkLine(CanonicalSecurityContext.Session session, String band,
                              CanonicalSecurityContext.Location location) {
        String ip = session != null ? session.getClientIp() : null;
        if (ip == null && band == null) {
            return null;
        }
        List<String> details = new ArrayList<>();
        if (band != null) {
            details.add(band);
        }
        if (location != null) {
            addPart(details, "zone ", location.getNetworkZone());
            addPart(details, "", location.getCity());
            addPart(details, "", location.getCountry());
            addPart(details, "ASN ", location.getAsn());
        }
        return networkAddress(session) + (details.isEmpty() ? "" : " (" + String.join(", ", details) + ")");
    }

    /** The sealed client address, or {@code address not known} (R1b-2: shared with the inspector). */
    static String networkAddress(CanonicalSecurityContext.Session session) {
        return firstText(session != null ? session.getClientIp() : null, "address not known");
    }

    private static String device(SecurityEvent event, CanonicalSecurityContext canonical,
                                 CurrentLearningContextSnapshot current) {
        CanonicalSecurityContext.Session session = canonical != null ? canonical.getSession() : null;
        CanonicalSecurityContext.Device device = canonical != null ? canonical.getDevice() : null;
        String value = deviceName(device, current);
        if (value == null) {
            String agent = session != null ? session.getUserAgent() : null;
            if (!StringUtils.hasText(agent)) {
                return null;
            }
            // The user agent is the requester's text: it is drawn once, as an untrusted text (N-INJ-1).
            value = "unparsed user agent";
        }
        return deviceLine(value, deviceSeen(hostDeclaredNewDevice(event), canonical), device);
    }

    /**
     * {@code Chrome/140 on WINDOWS (seen in past records, OS version 11, ...)}: the device name with whether it was seen
     * and the sealed device's details (R1b-7: shared with the inspector).
     */
    static String deviceLine(String name, String seen, CanonicalSecurityContext.Device device) {
        List<String> details = new ArrayList<>();
        if (seen != null) {
            details.add(seen);
        }
        if (device != null) {
            addPart(details, "OS version ", device.getOsVersion());
            addPart(details, "language ", device.getLanguage());
            addPart(details, "screen ", device.getScreenResolution());
            if (device.getFingerprintMatch() != null) {
                details.add(device.getFingerprintMatch() ? "fingerprint matches" : "fingerprint does not match");
            }
        }
        return name + (details.isEmpty() ? "" : " (" + String.join(", ", details) + ")");
    }

    /**
     * Whether the device was seen before, one fact with one source each time it is stated (W3-19): a value the host
     * declared is the host's; the engine's is the decision facts' comparison with the personal baseline, stated by the
     * decision facts only (Q-79 A2); without that comparison, a value the engine found in the past records says so.
     * R1b-7: shared with the inspector, which cannot know whether the host declared it.
     */
    static String deviceSeen(boolean hostDeclared, CanonicalSecurityContext canonical) {
        CanonicalSecurityContext.Session session = canonical != null ? canonical.getSession() : null;
        Boolean newDevice = session != null ? session.getNewDevice() : null;
        if (newDevice != null && hostDeclared) {
            return newDevice ? "new device per host" : "known device per host";
        }
        DecisionFacts facts = canonical != null ? canonical.getDecisionFacts() : null;
        Deviation compared = facts == null ? null : facts.deviations().stream()
                .filter(deviation -> deviation != null && deviation.dimension() == DeviationDimension.DEVICE
                        && deviation.compared())
                .findFirst().orElse(null);
        if (compared != null) {
            return null;
        }
        if (newDevice != null) {
            return newDevice ? "not seen in past records" : "seen in past records";
        }
        return null;
    }

    /** Whether the host declared the device new or known (the keys the canonical context provider reads). */
    private static boolean hostDeclaredNewDevice(SecurityEvent event) {
        Map<String, Object> metadata = event != null ? event.getMetadata() : null;
        return metadata != null && (metadata.get("isNewDevice") != null || metadata.get("is_new_device") != null);
    }

    private static String deviceName(CanonicalSecurityContext.Device device, CurrentLearningContextSnapshot current) {
        String value = current != null ? current.device() : null;
        return value != null ? value : sealedDeviceName(device);
    }

    /**
     * The device the sealed context names (the browser with its version, and the system), or null; the render takes
     * the unsealed current request snapshot's device first (R1b-2: shared with the inspector).
     */
    static String sealedDeviceName(CanonicalSecurityContext.Device device) {
        return device == null ? null : SecuritySemanticNormalizer.device(
                device.getBrowser() != null && device.getBrowserVersion() != null
                        ? device.getBrowser() + "/" + device.getBrowserVersion() : device.getBrowser(), device.getOs());
    }

    /** The user agent text when the device line cannot name a device (N-INJ-1), else null. */
    private static String unparsedUserAgent(CanonicalSecurityContext.Session session, CanonicalSecurityContext.Device device,
                                            CurrentLearningContextSnapshot current) {
        String agent = session != null ? session.getUserAgent() : null;
        return deviceName(device, current) == null && StringUtils.hasText(agent) ? agent : null;
    }

    // DECISION FACTS (entries the resolver does not compute)

    static String temporaryElevation(CanonicalSecurityContext.RoleScopeProfile roleScope) {
        if (!Boolean.TRUE.equals(roleScope.getTemporaryElevation())) {
            return "none";
        }
        List<String> parts = new ArrayList<>();
        parts.add("active");
        if (roleScope.getElevatedPrivilegeWindowActive() != null) {
            parts.add(roleScope.getElevatedPrivilegeWindowActive() ? "window open" : "window closed");
        }
        addPart(parts, "", roleScope.getElevationWindowSummary());
        // The reason is the host's own words: it is drawn once, in the UNTRUSTED TEXT block (W3-6).
        return String.join(", ", parts);
    }

    private static String authorizationEffect(SecurityEvent event, CanonicalSecurityContext canonical) {
        CanonicalSecurityContext.Authorization authorization = canonical != null ? canonical.getAuthorization() : null;
        if (authorization == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        String effect = authorizationEffectPart(authorization);
        if (effect != null) {
            // The provenance is the host's event metadata, which is not sealed.
            String provenance = metadata(event, "authorizationEffectProvenance");
            parts.add(effect + (provenance != null ? " (" + provenance + ")" : ""));
        }
        String failure = methodFailurePart(authorization);
        if (failure != null) {
            parts.add(failure);
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    /** {@code ALLOW by policy P-7 v2}: the effect and the deciding policy, or null (R1b-2: shared with the inspector). */
    static String authorizationEffectPart(CanonicalSecurityContext.Authorization authorization) {
        if (authorization == null || !StringUtils.hasText(authorization.getAuthorizationEffect())) {
            return null;
        }
        String effect = authorization.getAuthorizationEffect().trim();
        if (StringUtils.hasText(authorization.getPolicyId())) {
            effect += " by policy " + authorization.getPolicyId().trim()
                    + (StringUtils.hasText(authorization.getPolicyVersion()) ? " " + authorization.getPolicyVersion().trim() : "");
        }
        return effect;
    }

    /** {@code method failed with X after authorization}, or null (R1b-2: shared with the inspector). */
    static String methodFailurePart(CanonicalSecurityContext.Authorization authorization) {
        if (authorization == null || !StringUtils.hasText(authorization.getMethodExecutionFailure())) {
            return null;
        }
        return "method " + firstText(authorization.getMethodExecutionOutcome(), "failed") + " with "
                + authorization.getMethodExecutionFailure().trim() + " after authorization";
    }

    /** {@code break-glass declared (company record)}, or null (R1b-2: shared with the inspector). */
    static String breakGlass(CanonicalSecurityContext.FrictionProfile friction) {
        return friction != null && Boolean.TRUE.equals(friction.getBreakGlass())
                ? "break-glass declared (company record)" : null;
    }

    static String clientSignals(CanonicalSecurityContext.Intent intent) {
        if (intent == null) {
            return null;
        }
        Map<String, Boolean> signals = new LinkedHashMap<>();
        signals.put("bot UA", intent.getBotUserAgent());
        signals.put("TLS fingerprint changed", intent.getTlsFingerprintAltered());
        signals.put("abnormal header order", intent.getAbnormalHeaderOrder());
        signals.put("language mismatch", intent.getLanguageMismatch());
        signals.put("missing referer", intent.getMissingReferer());
        signals.put("impossible travel", intent.getImpossibleTravel());
        List<String> parts = new ArrayList<>();
        signals.forEach((name, value) -> {
            if (value != null) {
                parts.add(name + ": " + (value ? "yes" : "no"));
            }
        });
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    static String blockedUser(CanonicalSecurityContext canonical) {
        if (canonical == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        if (canonical.getSession() != null && Boolean.TRUE.equals(canonical.getSession().getBlockedUser())) {
            parts.add("blocked (session record)");
        }
        if (canonical.getFrictionProfile() != null && Boolean.TRUE.equals(canonical.getFrictionProfile().getBlockedUser())) {
            parts.add("blocked (company record)");
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    // PAST RECORDS

    /**
     * The state of the request's past record search; after an earlier search on the request timed out, it says that this
     * was the second search and how the first ended (N-MISS-1 D8).
     */
    /**
     * The reason the render names the past records unknown now with when the search did not finish or did not run
     * ({@code not retrieved, TIMEOUT}), else null (dictionary 1.4). N-INS-4: shared with the inspector.
     */
    static String notRetrievedReason(SecurityDecisionPromptSections.RagState rag) {
        String state = firstText(rag.retrievalState(), "UNKNOWN");
        boolean notRetrieved = !rag.searchExecuted()
                || PastRecordLineValues.NOT_RETRIEVED_STATES.contains(state.toUpperCase(Locale.ROOT));
        return notRetrieved ? PastRecordLineValues.NOT_RETRIEVED + ", " + state : null;
    }

    /** The reason the render names the counted facts unknown with when it draws no counts line (N-INS-4: shared). */
    static String countsUnknownReason(SecurityDecisionPromptSections.RagState rag) {
        String notRetrieved = notRetrievedReason(rag);
        return notRetrieved != null ? notRetrieved : "not counted";
    }

    static String pastRecordsState(SecurityDecisionPromptSections.RagState rag) {
        String state = searchState(rag);
        return StringUtils.hasText(rag.earlierRetrievalState())
                ? state + "; second search (first search " + rag.earlierRetrievalState().trim() + ")"
                : state;
    }

    private static String searchState(SecurityDecisionPromptSections.RagState rag) {
        String state = firstText(rag.retrievalState(), "UNKNOWN");
        if (!rag.searchExecuted() || PastRecordLineValues.NOT_RETRIEVED_STATES.contains(state.toUpperCase(Locale.ROOT))) {
            String reason = rag.absenceReason();
            return PastRecordLineValues.NOT_RETRIEVED + " (" + state
                    + (StringUtils.hasText(reason) && !reason.trim().equalsIgnoreCase(state) ? ": " + reason.trim() : "") + ")";
        }
        if (rag.relatedDocumentCount() == 0) {
            return PastRecordLineValues.NONE_FOUND + " (" + firstText(rag.absenceReason(), state) + ")";
        }
        return rag.relatedDocumentCount() + (rag.relatedDocumentCount() == 1 ? " record" : " records") + " of "
                + rag.candidateCount() + " candidates (" + rag.authorizedCount() + " authorized, " + rag.deniedCount()
                + " denied, relevance " + rag.relevance() + ", " + rag.projectionState() + ")";
    }

    /** The supporting comparable lines of the v19 supporting section, only when there are supporting cases. */
    static String supportingCases(int count, String section) {
        if (count <= 0 || section == null) {
            return null;
        }
        List<String> lines = new ArrayList<>();
        for (String line : section.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("SupportingComparable")) {
                lines.add(trimmed);
            }
        }
        return lines.isEmpty() ? null : String.join("; ", lines) + "; reference only";
    }

    // Helpers

    /** A v19 section's lines as one value, headers and blank lines left out, for entries W3-6 and W3-12 rewrite. */
    static String collapse(String section) {
        return collapse(section, Set.of());
    }

    /** As {@link #collapse(String)}, also leaving out the lines whose label the user removed (W3-5, principle 14). */
    static String collapse(String section, Set<String> removedLabels) {
        return collapse(section, removedLabels, Function.identity());
    }

    /** As {@link #collapse(String, Set)}, each line as the function leaves it; a line it leaves null is left out. */
    private static String collapse(String section, Set<String> removedLabels, Function<String, String> lineFacts) {
        if (!StringUtils.hasText(section)) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        for (String line : section.split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("===") && !removedLabels.contains(labelOf(trimmed))) {
                String facts = lineFacts.apply(trimmed);
                if (facts != null) {
                    parts.add(facts);
                }
            }
        }
        return parts.isEmpty() ? null : String.join("; ", parts);
    }

    /** The label of a v19 section line, {@code Seed policy} of {@code Seed policy: ...}; empty without one. */
    private static String labelOf(String line) {
        int colon = line.indexOf(": ");
        return colon > 0 ? line.substring(0, colon) : "";
    }

    private static boolean has(PromptBlock block, String name) {
        return SecurityDecisionPromptDictionary.ENTRIES.stream()
                .anyMatch(entry -> entry.block() == block && entry.name().equals(name));
    }

    private static Instant requestTime(SecurityEvent event, CanonicalSecurityContext canonical) {
        if (canonical != null && canonical.getRequestObservedAt() != null) {
            return canonical.getRequestObservedAt();
        }
        return event != null ? event.getTimestamp() : null;
    }

    private static String clock(Instant at, ZoneId zone) {
        LocalDateTime local = LocalDateTime.ofInstant(at, zone);
        return String.format(Locale.ROOT, "%02d:%02d", local.getHour(), local.getMinute());
    }

    /** {@code (3 min before this request)} after a time of the event clock, or nothing without the request time. */
    private static String relative(Instant time, Instant at) {
        String relative = RelativeTime.of(time, at);
        return relative != null ? " (" + relative + ")" : "";
    }

    /** A value on the event clock: a time, an hour or a day of the week (W3-13). */
    private static void clockedValue(PromptEntryValues.Builder values, PromptBlock block, String name, String value) {
        values.value(block, name, value);
        if (StringUtils.hasText(value)) {
            values.clocked(block, name);
        }
    }

    private static String number(long value) {
        return String.format(Locale.ROOT, "%,d", value);
    }

    private static String names(Collection<String> values) {
        return names(values, ", ");
    }

    private static String names(Collection<String> values, String separator) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        List<PromptListItem> items = new ArrayList<>();
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                items.add(PromptListItem.named(value.trim(), value.trim()));
            }
        }
        List<String> sorted = PromptListOrder.NAME_ASCENDING.sort(items).stream().map(PromptListItem::text).distinct().toList();
        return sorted.isEmpty() ? null : String.join(separator, sorted);
    }

    private static String counted(Map<String, Integer> counts) {
        if (counts == null || counts.isEmpty()) {
            return null;
        }
        List<PromptListItem> items = new ArrayList<>();
        counts.forEach((name, count) -> {
            if (StringUtils.hasText(name) && count != null) {
                items.add(PromptListItem.counted(name + " " + count, name, count));
            }
        });
        List<String> sorted = PromptListOrder.FREQUENCY_DESCENDING.sort(items).stream().map(PromptListItem::text).toList();
        return sorted.isEmpty() ? null : String.join(", ", sorted);
    }

    private static Map<String, Integer> classCounts(List<String> classes) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        if (classes == null) {
            return counts;
        }
        for (String value : classes) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            int separator = value.indexOf('=');
            if (separator > 0) {
                try {
                    counts.put(value.substring(0, separator).trim(), Integer.parseInt(value.substring(separator + 1).trim()));
                    continue;
                }
                catch (NumberFormatException ignored) {
                    // a class without a count keeps its name below
                }
            }
            counts.putIfAbsent(value.trim(), 0);
        }
        return counts;
    }

    /** Ascending numbers with runs of consecutive ones joined: {@code 9-11, 13, 17}. */
    private static String ranges(List<Integer> values, IntFunction<String> name) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        List<Integer> sorted = values.stream().filter(Objects::nonNull).distinct().sorted().toList();
        List<String> parts = new ArrayList<>();
        int start = sorted.get(0);
        int previous = start;
        for (int index = 1; index <= sorted.size(); index++) {
            Integer value = index < sorted.size() ? sorted.get(index) : null;
            if (value != null && value == previous + 1) {
                previous = value;
                continue;
            }
            parts.add(start == previous ? name.apply(start) : name.apply(start) + "-" + name.apply(previous));
            if (value != null) {
                start = value;
                previous = value;
            }
        }
        return String.join(", ", parts);
    }

    private static Instant parseInstant(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        }
        catch (RuntimeException exception) {
            try {
                return OffsetDateTime.parse(value.trim()).toInstant();
            }
            catch (RuntimeException ignored) {
                return null;
            }
        }
    }

    private static String metadata(SecurityEvent event, String key) {
        if (event == null || event.getMetadata() == null) {
            return null;
        }
        Object value = event.getMetadata().get(key);
        return value != null && StringUtils.hasText(value.toString()) ? value.toString().trim() : null;
    }

    private static void addPart(List<String> parts, String prefix, String value) {
        if (StringUtils.hasText(value)) {
            parts.add(prefix + value.trim());
        }
    }

    private static String firstText(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }
}
