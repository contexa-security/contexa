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
package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.baseline.BaselineView;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.model.ContextCoverageReport;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptDictionaryEntry;
import io.contexa.contexacore.autonomous.context.prompt.PromptSlotRenderer;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.autonomous.tiered.prompt.BaselineLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.DecisionFactLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.RequestLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import io.contexa.contexacore.autonomous.tiered.prompt.SessionLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.UnknownLineValues;

import io.contexa.contexacore.autonomous.tiered.prompt.UntrustedTextSources;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Whether the facts a v20 prompt draws say what their sealed source says, compared field by field with the sealed
 * canonical context and not by rendering the prompt again (a render would repeat a renderer's mistake). A line whose
 * source was not sealed cannot be compared and is counted as such, with the reason.
 *
 * <p>The REQUEST block: the subject's user id, the request time on the sealed event clock, the roles and permissions
 * (as sets), the action family, method and path template, the target's variables, label and category, the requested
 * size, the resource class, the network address and zone, and the device name. A field a line takes first from the
 * unsealed current request snapshot and only then from the sealed context is compared when the sealed one is there: a
 * difference then means the two sources say different things.</p>
 */
public final class FactAccuracyCheck implements PromptInspectionCheck {

    public static final String CODE = "FACT_ACCURACY";

    private static final String CONTEXT = "canonicalContext.";
    private static final String SEALED_BASELINE_STATE = PromptExecutionMetadata.PROMPT_BASELINE_STATUS;
    private static final String STATE_SOURCE = "executionMetadata." + SEALED_BASELINE_STATE;
    /** The baseline state the evidence line named before Q-79 A1: {@code state SPARSE_PERSONAL_HISTORY}. */
    private static final Pattern FORMER_STATE = Pattern.compile("(?:^|, )state ([A-Z_]+)(?=$|[,;])");
    private static final PromptBlock REQUEST = PromptBlock.REQUEST;
    /** {@code FAMILY (source) METHOD (template ..., method ...)}: the family, then the method when one is drawn. */
    private static final Pattern ACTION = Pattern.compile("^(\\S+) \\([^)]*\\)(?: ([A-Z]+))?(?: \\((.*)\\))?$");
    private static final String CATEGORY = ", category ";
    /** {@code source=<source>; "<text>"}: an untrusted text line. */

    /** The entries this check compares with their sealed sources (BLOCK.Entry). */
    public static final Set<String> COMPARED = Set.of(
            "USER_BASELINE.Evidence", "USER_BASELINE.BaselineStatus", "USER_BASELINE.UsualHours", "USER_BASELINE.UsualDays",
            "USER_BASELINE.UsualNetworks", "USER_BASELINE.UsualDevices", "USER_BASELINE.UsualLoginMethods",
            "USER_BASELINE.UsualTargets", "USER_BASELINE.UsualActions", "USER_BASELINE.UsualResourceClass",
            "USER_BASELINE.UsualExportSize", "USER_BASELINE.UsualRequestRate", "USER_BASELINE.UsualSessionLength",
            "USER_BASELINE.UsualPrivilegedActions", "USER_BASELINE.SeasonalPattern", "USER_BASELINE.KnownRareTasks",
            "USER_BASELINE.WorkProfile",
            "SESSION.SessionAge", "SESSION.LoginMethod", "SESSION.ChallengeVerified", "SESSION.RecentMfaElsewhere",
            "SESSION.FailedLogins", "SESSION.MfaFailures", "SESSION.RequestsInSession", "SESSION.RecentRequests",
            "SESSION.ConcurrentSessions", "SESSION.PasswordAge", "SESSION.RecentSensitiveAccess", "SESSION.RecentDenied",
            "REQUEST.Subject", "REQUEST.Roles", "REQUEST.Permissions", "REQUEST.Time", "REQUEST.Action",
            "REQUEST.Target", "REQUEST.Size", "REQUEST.ResourceClass", "REQUEST.Network", "REQUEST.Device",
            "DECISION_FACTS.RecentPermissionChanges", "DECISION_FACTS.TemporaryElevation",
            "DECISION_FACTS.AuthorizationEffect", "DECISION_FACTS.ClientSignals",
            "DECISION_FACTS.BlockedUser", "DECISION_FACTS.BreakGlass",
            "UNKNOWN.Coverage", "UNTRUSTED_TEXT.UntrustedText{i}");

    /** The entries another check inspects, with that check's code. */
    public static final Map<String, String> INSPECTED_ELSEWHERE = Map.ofEntries(
            Map.entry("DECISION_FACTS.DeviationsFromBaseline", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.SameAsBaseline", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.Policy", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.PolicySatisfied", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.Approval", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.Assignment", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.Ticket", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.OnCall", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.Travel", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.RepeatInSession", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.RoleScope", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.DataConflicts", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.Movement", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.SessionDeviceChange", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.SessionNetworkChange", DecisionFactMatchCheck.CODE),
            Map.entry("DECISION_FACTS.PeerCohort", DecisionFactMatchCheck.CODE),
            Map.entry("PAST_RECORDS.PastRecordsState", PastRecordNotationCheck.CODE),
            Map.entry("PAST_RECORDS.PastRecordCounts", PastRecordNotationCheck.CODE),
            Map.entry("PAST_RECORDS.PastRecord{i}", PastRecordNotationCheck.CODE),
            Map.entry("PAST_RECORDS.PastDeniedDecision{i}", PastRecordNotationCheck.CODE),
            Map.entry("UNKNOWN.Unknown", UnknownDeclaredCheck.CODE));

    /**
     * The entries whose sources the package does not keep or the inspector does not draw again: what a drawn line of
     * them would be compared with, and why it is not.
     */
    public static final Map<String, NotComparable> NOT_COMPARABLE = Map.ofEntries(
            Map.entry("USER_BASELINE.PeerReference", new NotComparable("learningContextEvidence",
                    "the peer reference reads the supporting baseline and the behaviour analysis, which are not sealed")),
            Map.entry("DECISION_FACTS.Delegation", new NotComparable("canonicalContext.delegation",
                    "the delegation line is the v19 delegation section's text; the inspector does not render again")),
            Map.entry("DECISION_FACTS.ThreatMatch", new NotComparable("behaviorAnalysis",
                    "the threat match reads the behaviour analysis, which is not sealed")),
            Map.entry("PAST_RECORDS.SupportingCases", new NotComparable("learningContextEvidence",
                    "the supporting cases read the learning evidence, which is not sealed")),
            Map.entry("PAST_RECORDS.ValidatedCases", new NotComparable("canonicalContext",
                    "the validated cases are the v19 reasoning memory section's text; the inspector does not render again")),
            Map.entry("SECOND_PASS.FirstPassVerdict", new NotComparable("firstPassPrompt",
                    "the second pass block is drawn from the first pass, whose prompt is not sealed apart (W6-6)")),
            Map.entry("SECOND_PASS.NewlyKnown", new NotComparable("firstPassPrompt",
                    "the second pass block is drawn from the first pass, whose prompt is not sealed apart (W6-6)")),
            Map.entry("SECOND_PASS.NewPastRecord{i}", new NotComparable("firstPassPrompt",
                    "the second pass block is drawn from the first pass, whose prompt is not sealed apart (W6-6)")));

    /** Why a drawn line of an entry is not compared: the source it reads and the reason. */
    public record NotComparable(String source, String reason) {
    }

    /** The USER BASELINE lines an observed baseline view gives on its own. */
    private static final List<String> VIEW_LINES = List.of("UsualHours", "UsualDays", "UsualTargets", "UsualActions",
            "UsualResourceClass", "UsualExportSize", "UsualRequestRate", "UsualSessionLength", "UsualPrivilegedActions",
            "KnownRareTasks");

    /** Where a part of a drawn line the render may take from an unsealed source stands in a line's form. */
    private static final String OPEN = "\u0000";
    /** What a line's expected text shows for a part the sealed sources do not give. */
    private static final String NOT_SEALED = "<not sealed>";
    private static final String FACTS_NOT_KNOWN = "the request facts the render takes it from are not sealed or do not read";

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return true;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        CanonicalSecurityContext context = tally.subject().canonicalContext();
        if (context == null) {
            tally.unverifiable(tally.unverifiableFinding().sourceRef(CONTEXT.substring(0, CONTEXT.length() - 1))
                    .reason(tally.subject().canonicalContextSealed()
                            ? "the sealed canonical context does not read"
                            : "the canonical context is not sealed, so no drawn fact can be compared")
                    .build());
            return;
        }
        Map<String, InspectedPrompt.Line> request = lines(tally.subject().prompt(), REQUEST);
        subject(tally, request.get("Subject"), context);
        roles(tally, request.get("Roles"), context);
        permissions(tally, request.get("Permissions"), context);
        time(tally, request.get("Time"), context);
        action(tally, request.get("Action"), context);
        target(tally, request.get("Target"), context);
        size(tally, request.get("Size"), context);
        resourceClass(tally, request.get("ResourceClass"), context);
        network(tally, request.get("Network"), context);
        device(tally, request.get("Device"), context);
        baseline(tally, lines(tally.subject().prompt(), PromptBlock.USER_BASELINE), context);
        session(tally, lines(tally.subject().prompt(), PromptBlock.SESSION), context);
        Map<String, InspectedPrompt.Line> facts = lines(tally.subject().prompt(), PromptBlock.DECISION_FACTS);
        authorizationEffect(tally, facts.get("AuthorizationEffect"), context);
        expected(tally, facts.get("ClientSignals"), DecisionFactLineValues.clientSignals(context.getIntent()), CONTEXT + "intent",
                "client signals");
        boolean sessionBlocked = context.getSession() != null && Boolean.TRUE.equals(context.getSession().getBlockedUser());
        expected(tally, facts.get("BlockedUser"), DecisionFactLineValues.blockedUser(context),
                CONTEXT + (sessionBlocked ? "session.blockedUser" : "frictionProfile.blockedUser"), "blocked user");
        expected(tally, facts.get("BreakGlass"), DecisionFactLineValues.breakGlass(context.getFrictionProfile()),
                CONTEXT + "frictionProfile.breakGlass", "break-glass");
        CanonicalSecurityContext.RoleScopeProfile roleScope = context.getRoleScopeProfile();
        listed(tally, facts.get("RecentPermissionChanges"),
                roleScope != null ? roleScope.getRecentPermissionChanges() : List.of(),
                "roleScopeProfile.recentPermissionChanges", "permission changes", "; ");
        expected(tally, facts.get("TemporaryElevation"), roleScope != null && roleScope.getTemporaryElevation() != null
                        ? DecisionFactLineValues.temporaryElevation(roleScope) : null,
                CONTEXT + "roleScopeProfile.temporaryElevation", "temporary elevation");
        coverage(tally, lines(tally.subject().prompt(), PromptBlock.UNKNOWN).get("Coverage"), context);
        untrusted(tally, context, tally.subject().sources().requestFacts());
        notComparable(tally);
    }

    /** A drawn line of an entry whose source the package does not keep is counted as not comparable, with why. */
    private void notComparable(PromptInspectionTally tally) {
        for (InspectedPrompt.Line line : tally.subject().prompt().lines()) {
            if (line.kind() != InspectedPrompt.Kind.ENTRY || line.block() == null) {
                continue;
            }
            SecurityDecisionPromptDictionary.ENTRIES.stream()
                    .filter(entry -> entry.block() == line.block() && entry.matchesLabel(line.entryLine().label()))
                    .findFirst()
                    .map(entry -> NOT_COMPARABLE.get(entry.block().name() + "." + entry.name()))
                    .ifPresent(why -> tally.unverifiable(tally.unverifiableFinding().block(line.block().title())
                            .entry(line.entryLine().label()).factId(line.factId()).lineNumber(line.number())
                            .actual(line.entryLine().value()).sourceRef(why.source()).reason(why.reason()).build()));
        }
    }

    /** The coverage and bridge levels and the missing facts of the sealed coverage report and bridge. */
    private static void coverage(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        ContextCoverageReport report = context.getCoverage();
        CanonicalSecurityContext.Bridge bridge = context.getBridge();
        String value = line.entryLine().value();
        if (report == null && bridge == null) {
            mismatch(tally, line, "no line (the sealed context holds no coverage report or bridge)", value,
                    CONTEXT + "coverage", "the prompt states a coverage the sealed context does not hold");
            return;
        }
        List<String> expected = new ArrayList<>();
        if (report != null) {
            expected.add(UnknownLineValues.coverageLevel(report));
            String missing = UnknownLineValues.missingFacts(report);
            if (missing != null) {
                expected.add(missing);
            }
        }
        expected.add(UnknownLineValues.bridgeLevel(bridge));
        for (String part : expected) {
            if (!statesPart(value, part)) {
                mismatch(tally, line, part, value, CONTEXT + (part.startsWith("bridge") ? "bridge" : "coverage"),
                        "the coverage line does not state the sealed coverage and bridge levels");
                return;
            }
        }
        // R1b-7 (P3 extra 35): the whole line, with the coverage warnings and the bridge's hints.
        CanonicalSecurityContext.WorkProfile workProfile = context.getWorkProfile();
        BaselineView view = workProfile != null ? workProfile.getBaselineView() : null;
        whole(tally, line, CONTEXT + "coverage", "coverage", List.of(), parts -> UnknownLineValues.coverage(context, view));
    }

    /**
     * Whether the coverage line states the part as one of its parts: at its start or after {@code "; "}, followed by
     * the end, {@code "; "} or {@code ": "}. The levels are pointed at first; the whole line follows (R1b-7).
     */
    private static boolean statesPart(String value, String part) {
        return Pattern.compile("(^|; )" + Pattern.quote(part) + "($|; |: )").matcher(value).find();
    }

    /** The untrusted texts whose sources are sealed say those texts, as the render quotes and cuts them. */
    private static void untrusted(PromptInspectionTally tally, CanonicalSecurityContext context,
                                  Map<String, Object> requestFacts) {
        CanonicalSecurityContext.Resource resource = context.getResource();
        CanonicalSecurityContext.RoleScopeProfile roleScope = context.getRoleScopeProfile();
        for (InspectedPrompt.Line line : tally.subject().prompt().lines()) {
            if (line.kind() != InspectedPrompt.Kind.ENTRY || line.block() != PromptBlock.UNTRUSTED_TEXT) {
                continue;
            }
            Matcher drawn = PromptSlotRenderer.UNTRUSTED_LINE.matcher(line.entryLine().value());
            if (!drawn.matches()) {
                mismatch(tally, line, "source=<source>; \"<text>\"", line.entryLine().value(), CONTEXT,
                        "the untrusted text does not read as its source and quoted text");
                continue;
            }
            String source = drawn.group(1);
            switch (source) {
                case UntrustedTextSources.DOCUMENT_DESCRIPTION -> text(tally, line, source,
                        resource != null ? resource.getAuthorText() : null, CONTEXT + "resource.authorText");
                case UntrustedTextSources.BUSINESS_LABEL -> text(tally, line, source,
                        resource != null ? resource.getBusinessLabel() : null, CONTEXT + "resource.businessLabel");
                case UntrustedTextSources.ANOMALY_SIGNAL_HEADER -> text(tally, line, source,
                        context.getIntent() != null ? context.getIntent().getUntrustedAnomalySignalClaim() : null,
                        CONTEXT + "intent.untrustedAnomalySignalClaim");
                case UntrustedTextSources.ELEVATION_REASON -> text(tally, line, source,
                        roleScope != null ? roleScope.getTemporaryElevationReason() : null,
                        CONTEXT + "roleScopeProfile.temporaryElevationReason");
                case UntrustedTextSources.USER_AGENT -> text(tally, line, source,
                        context.getSession() != null ? context.getSession().getUserAgent() : null,
                        CONTEXT + "session.userAgent");
                case UntrustedTextSources.REQUEST_PATH -> {
                    String path = resource != null ? text(resource.getRequestPath()) : null;
                    if (path == null && tally.subject().unreadSources().contains(PromptInspectionSources.REQUEST_FACTS)) {
                        unverifiable(tally, line, "requestFactsJson.requestPath", "the sealed request facts do not read");
                    }
                    else {
                        text(tally, line, source, path != null ? path : asText(requestFacts.get("requestPath")),
                                path != null ? CONTEXT + "resource.requestPath" : "requestFactsJson.requestPath");
                    }
                }
                case UntrustedTextSources.SESSION_REQUEST_PATHS -> text(tally, line, source,
                        SessionLineValues.sessionPaths(context.getSessionNarrativeProfile()),
                        CONTEXT + "sessionNarrativeProfile.sessionDecisions");
                case UntrustedTextSources.CLAIMED_TICKET -> ticket(tally, line, source, context);
                case UntrustedTextSources.REQUEST_BODY, UntrustedTextSources.THREAT_KNOWLEDGE -> unverifiable(tally, line,
                        CONTEXT + "untrustedText", "the " + source + " is not sealed");
                default -> mismatch(tally, line, "a known untrusted text source", source, CONTEXT,
                        "the untrusted text names a source the render does not draw");
            }
        }
    }

    private static void ticket(PromptInspectionTally tally, InspectedPrompt.Line line, String source,
                               CanonicalSecurityContext context) {
        CanonicalSecurityContext.FrictionProfile friction = context.getFrictionProfile();
        List<String> claimed = friction == null || friction.getTicketRecords() == null ? List.of()
                : friction.getTicketRecords().stream()
                .filter(record -> record != null && Boolean.TRUE.equals(record.getClaimedByRequester())
                        && text(record.getTicketId()) != null)
                .map(CanonicalSecurityContext.TicketRecord::getTicketId).toList();
        for (String id : claimed) {
            if (quoted(source, id, line.entryLine().value())) {
                tally.matched(line);
                return;
            }
        }
        mismatch(tally, line, claimed.isEmpty() ? "no line (the sealed records hold no ticket the requester named)"
                        : "one of " + claimed, line.entryLine().value(), CONTEXT + "frictionProfile.ticketRecords",
                "the ticket is not one the sealed records say the requester named");
    }

    /** The line quotes the sealed text as the render does, whole or cut with the count of what was cut. */
    private static void text(PromptInspectionTally tally, InspectedPrompt.Line line, String source, String sealed,
                             String sourceRef) {
        if (sealed == null || sealed.isBlank()) {
            mismatch(tally, line, "no line (the sealed context holds no such text)", line.entryLine().value(), sourceRef,
                    "the prompt quotes a text the sealed context does not hold");
            return;
        }
        if (quoted(source, sealed, line.entryLine().value())) {
            tally.matched(line);
            return;
        }
        mismatch(tally, line, PromptSlotRenderer.encodeValue(PromptSlotRenderer.untrustedText(source, sealed, Integer.MAX_VALUE)),
                line.entryLine().value(), sourceRef, "the quoted text is not the sealed one");
    }

    private static boolean quoted(String source, String sealed, String drawn) {
        if (PromptSlotRenderer.encodeValue(PromptSlotRenderer.untrustedText(source, sealed, Integer.MAX_VALUE)).equals(drawn)) {
            return true;
        }
        Matcher cut = PromptSlotRenderer.CUT.matcher(drawn.substring(0, Math.max(0, drawn.length() - 1)));
        if (!cut.find()) {
            return false;
        }
        String stripped = sealed.strip();
        int kept = stripped.codePointCount(0, stripped.length()) - Integer.parseInt(cut.group(1));
        return kept >= 1 && PromptSlotRenderer.encodeValue(PromptSlotRenderer.untrustedText(source, sealed, kept)).equals(drawn);
    }

    private static String asText(Object value) {
        return value == null ? null : text(value.toString());
    }

    /**
     * The USER BASELINE lines an observed baseline view gives on its own, compared with the sealed view through the
     * render's own function ({@link BaselineLineValues}), and the seasonal pattern of the sealed work profile. The
     * networks, login methods and devices fall back to the unsealed personal baseline when the view holds none; such a
     * line is compared only when the view holds the values.
     */
    private static void baseline(PromptInspectionTally tally, Map<String, InspectedPrompt.Line> lines,
                                 CanonicalSecurityContext context) {
        CanonicalSecurityContext.WorkProfile workProfile = context.getWorkProfile();
        BaselineView view = workProfile != null ? workProfile.getBaselineView() : null;
        String source = CONTEXT + "workProfile.baselineView";
        Map<String, String> drawnFromView = view != null && view.observed() ? BaselineLineValues.of(view) : Map.of();
        // P3-extra-41: of a user of whom nothing personal is known no view is sealed, and the render can only say that
        // the usual values are not learned; the sealed state is then the source.
        boolean nothingLearned = view == null && BaselineLineValues.NONE.equals(sealedBaselineState(tally));
        for (String name : VIEW_LINES) {
            InspectedPrompt.Line line = lines.get(name);
            if (line == null) {
                continue;
            }
            if (nothingLearned) {
                notLearned(tally, line, name);
                continue;
            }
            if (view == null) {
                unverifiable(tally, line, source, "the baseline view is not sealed");
                continue;
            }
            String expected = drawnFromView.get(name);
            if (expected == null) {
                expected = missingText(PromptBlock.USER_BASELINE, name);
            }
            // A line the dictionary leaves out without a value is not drawn when the sealed view holds none.
            compare(tally, line, expected != null ? expected : "no line (the sealed view holds no value)",
                    line.entryLine().value(), source, "the baseline line is not what the sealed view says");
        }
        listedFromView(tally, lines.get("UsualNetworks"), view, view != null ? view.usualNetworks() : List.of(), source);
        listedFromView(tally, lines.get("UsualLoginMethods"), view, view != null ? view.usualLoginMethods() : List.of(),
                source);
        InspectedPrompt.Line devices = lines.get("UsualDevices");
        if (devices != null) {
            if (view != null && !view.usualDevices().isEmpty()) {
                listed(tally, devices, view.usualDevices(), "workProfile.baselineView", "usual devices", ", ");
            }
            else if (nothingLearned) {
                notLearned(tally, devices, "UsualDevices");
            }
            else {
                unverifiable(tally, devices, source,
                        "the usual devices come from browsers and systems that may be the unsealed personal baseline's");
            }
        }
        expected(tally, lines.get("SeasonalPattern"),
                workProfile != null ? text(workProfile.getSeasonalBusinessProfile()) : null,
                CONTEXT + "workProfile.seasonalBusinessProfile", "seasonal pattern");
        InspectedPrompt.Line profile = lines.get("WorkProfile");
        if (profile != null && view == null) {
            unverifiable(tally, profile, source, "the baseline view is not sealed");
        }
        else if (profile != null) {
            String expected = view.observed() ? BaselineLineValues.workProfile(workProfile, view) : null;
            expected(tally, profile, expected, source, "work profile");
        }
        evidence(tally, lines.get("Evidence"), view, context, source);
        baselineStatus(tally, lines.get("BaselineStatus"));
    }

    /**
     * R1b-1: the status line names the baseline state the render sealed (W3-19); its reasons read the personal baseline
     * snapshot, which is not sealed, so the state is what is compared. A package that seals no state cannot be compared.
     */
    private static void baselineStatus(PromptInspectionTally tally, InspectedPrompt.Line line) {
        if (line == null) {
            return;
        }
        String state = sealedBaselineState(tally);
        if (state == null) {
            unverifiable(tally, line, STATE_SOURCE, "the package seals no baseline state");
            return;
        }
        compare(tally, line, state, head(line.entryLine().value()), STATE_SOURCE,
                "the status line does not state the baseline state the render sealed");
    }

    /** The baseline state the render sealed, or null when the package seals none. */
    private static String sealedBaselineState(PromptInspectionTally tally) {
        Object sealedState = tally.subject().executionMetadata().get(SEALED_BASELINE_STATE);
        return sealedState != null && !sealedState.toString().isBlank() ? sealedState.toString().trim() : null;
    }

    /**
     * A usual line of a user without any learning: the dictionary's missing text, by the sealed NONE state; a line the
     * dictionary leaves out without a value is not drawn at all.
     */
    private static void notLearned(PromptInspectionTally tally, InspectedPrompt.Line line, String name) {
        String missing = missingText(PromptBlock.USER_BASELINE, name);
        compare(tally, line, missing != null ? missing : "no line (nothing is learned)", line.entryLine().value(),
                STATE_SOURCE, "a user of whom nothing is learned has no usual value on this line");
    }

    /**
     * The evidence line (dictionary 1.3): with an observed view, the sealed view's window and observations; without one,
     * the sealed trust profiles it names. The baseline state is BaselineStatus's only (Q-79 A1); a line in the form
     * before Q-79 still names it, and then it is the state the render sealed (W3-19), not comparable when the package
     * seals none.
     */
    private static void evidence(PromptInspectionTally tally, InspectedPrompt.Line line, BaselineView view,
                                 CanonicalSecurityContext context, String source) {
        if (line == null) {
            return;
        }
        String value = line.entryLine().value();
        Matcher former = FORMER_STATE.matcher(value);
        boolean namesState = former.find();
        if (view != null && view.observed()) {
            for (String part : List.of(BaselineLineValues.evidenceWindow(view), BaselineLineValues.evidenceObservations(view))) {
                if (!value.contains(part)) {
                    mismatch(tally, line, part, value, source, "the evidence line does not state the sealed view");
                    return;
                }
            }
        }
        else {
            List<String> collectors = context.getContextTrustProfiles() == null ? List.of()
                    : context.getContextTrustProfiles().stream().filter(Objects::nonNull)
                    .map(BaselineLineValues::collectorName)
                    .toList();
            if (collectors.isEmpty() && !namesState) {
                if (view == null) {
                    unverifiable(tally, line, source, "the baseline view and the trust profiles are not sealed");
                    return;
                }
                mismatch(tally, line, "no line (the sealed context holds no evidence)", value,
                        CONTEXT + "contextTrustProfiles", "the evidence line states evidence the sealed context does not hold");
                return;
            }
            for (String collector : collectors) {
                if (!value.contains(collector)) {
                    mismatch(tally, line, collector, value, CONTEXT + "contextTrustProfiles",
                            "the evidence line does not name a sealed trust profile");
                    return;
                }
            }
        }
        if (namesState) {
            Object sealedState = tally.subject().executionMetadata().get(SEALED_BASELINE_STATE);
            String state = sealedState != null && !sealedState.toString().isBlank() ? sealedState.toString().trim() : null;
            if (state == null) {
                unverifiable(tally, line, STATE_SOURCE, "the package seals no baseline state");
                return;
            }
            if (!state.equals(former.group(1))) {
                mismatch(tally, line, "state " + state, value, STATE_SOURCE,
                        "the evidence line does not state the baseline state the status line states");
                return;
            }
        }
        tally.matched(line);
    }

    /** A view list line: compared as a set when the sealed view holds values, else it may be the personal baseline's. */
    private static void listedFromView(PromptInspectionTally tally, InspectedPrompt.Line line, BaselineView view,
                                       List<String> values, String source) {
        if (line == null) {
            return;
        }
        if (view != null && !values.isEmpty()) {
            listed(tally, line, values, "workProfile.baselineView", line.entryLine().label(), ", ");
            return;
        }
        String missing = missingText(PromptBlock.USER_BASELINE, line.entryLine().label());
        if (missing != null && missing.equals(line.entryLine().value())) {
            tally.matched(line);
            return;
        }
        unverifiable(tally, line, source, "the sealed view holds no values, so the line is the unsealed personal "
                + "baseline's");
    }

    /**
     * The SESSION block: the session age and its basis, the login method (the sealed authentication state's method,
     * else the session's type) and whether MFA was verified, the challenge time on the sealed clock, an MFA elsewhere,
     * the counts of the session and the observed scope, the session's decisions and the recent denials.
     */
    private void session(PromptInspectionTally tally, Map<String, InspectedPrompt.Line> lines,
                         CanonicalSecurityContext context) {
        CanonicalSecurityContext.Session session = context.getSession();
        CanonicalSecurityContext.SessionNarrativeProfile narrative = context.getSessionNarrativeProfile();
        CanonicalSecurityContext.ObservedScope scope = context.getObservedScope();
        Instant at = context.getRequestObservedAt();
        ZoneId zone = tally.subject().eventZone();
        expected(tally, lines.get("SessionAge"), narrative != null && narrative.getSessionAgeMinutes() != null
                        ? SessionLineValues.sessionAge(narrative.getSessionAgeMinutes(), narrative.getSessionAgeBasis())
                        : null,
                CONTEXT + "sessionNarrativeProfile.sessionAgeMinutes", "session age");
        loginMethod(tally, lines.get("LoginMethod"), session);
        if (session != null) {
            InspectedPrompt.Line challenge = lines.get("ChallengeVerified");
            Instant verified = instant(session.getChallengeVerifiedAt());
            if (challenge != null && verified != null && zone == null) {
                unverifiable(tally, challenge, PromptInspectionSubject.EVENT_TIME_ZONE_REF, "the event time zone is not sealed");
            }
            else {
                expected(tally, challenge, verified != null
                                ? SessionLineValues.challengeVerified(verified, at, zone)
                                : missingText(PromptBlock.SESSION, "ChallengeVerified"),
                        CONTEXT + "session.challengeVerifiedAt", "challenge verification");
            }
            Instant elsewhere = instant(session.getRecentMfaElsewhereAt());
            InspectedPrompt.Line mfaElsewhere = lines.get("RecentMfaElsewhere");
            if (mfaElsewhere != null && elsewhere != null && at == null) {
                unverifiable(tally, mfaElsewhere, CONTEXT + "requestObservedAt", "the request time is not sealed");
            }
            else {
                expected(tally, mfaElsewhere, SessionLineValues.mfaElsewhere(elsewhere, at),
                        CONTEXT + "session.recentMfaElsewhereAt", "MFA elsewhere");
            }
            expected(tally, lines.get("FailedLogins"), SessionLineValues.failedLogins(session),
                    CONTEXT + "session.failedLoginAttempts", "failed login count");
            expected(tally, lines.get("MfaFailures"), SessionLineValues.mfaFailures(session),
                    CONTEXT + "session.recentMfaFailureCount", "MFA failure count");
            expected(tally, lines.get("RecentRequests"),
                    SessionLineValues.recentRequests(session, context.getSessionNarrativeProfile()),
                    CONTEXT + "session.recentRequestCount", "recent request count");
            expected(tally, lines.get("ConcurrentSessions"), SessionLineValues.concurrentSessions(session),
                    CONTEXT + "session.concurrentSessions", "concurrent session count");
            expected(tally, lines.get("PasswordAge"), SessionLineValues.passwordAge(session),
                    CONTEXT + "session.passwordAgeDays", "password age");
        }
        expected(tally, lines.get("RecentSensitiveAccess"), SessionLineValues.recentSensitiveAccess(scope),
                CONTEXT + "observedScope.recentSensitiveAccessCount", "recent sensitive access count");
        List<SessionDecisionRecord> decisions = narrative != null ? narrative.getSessionDecisions() : null;
        if (decisions != null) {
            InspectedPrompt.Line requests = lines.get("RequestsInSession");
            if (requests != null && zone == null && decisions.stream().anyMatch(d -> d != null && d.at() != null)) {
                unverifiable(tally, requests, PromptInspectionSubject.EVENT_TIME_ZONE_REF, "the event time zone is not sealed");
            }
            else {
                String drawn = SessionLineValues.requestsInSession(decisions,
                        SessionLineValues.currentTarget(context.getResource()), at, zone);
                expected(tally, requests, drawn != null ? drawn : missingText(PromptBlock.SESSION, "RequestsInSession"),
                        CONTEXT + "sessionNarrativeProfile.sessionDecisions", "session's requests");
            }
        }
        InspectedPrompt.Line denied = lines.get("RecentDenied");
        if (denied != null && zone == null && decisions != null) {
            unverifiable(tally, denied, PromptInspectionSubject.EVENT_TIME_ZONE_REF, "the event time zone is not sealed");
        }
        else {
            expected(tally, denied, SessionLineValues.recentDenied(decisions, scope, zone),
                    CONTEXT + (decisions != null && !decisions.isEmpty()
                            ? "sessionNarrativeProfile.sessionDecisions" : "observedScope.recentDeniedAccessCount"),
                    "recent denials");
        }
    }

    private void loginMethod(PromptInspectionTally tally, InspectedPrompt.Line line,
                             CanonicalSecurityContext.Session session) {
        if (line == null) {
            return;
        }
        if (tally.subject().unreadSources().contains(PromptInspectionSources.AUTH_STATE)) {
            unverifiable(tally, line, "authStateJson.authMethod", "the sealed authentication state does not read");
            return;
        }
        Object sealedMethod = tally.subject().sources().authState().get("authMethod");
        String raw = sealedMethod != null ? text(sealedMethod.toString()) : null;
        String typed = session != null ? text(session.getAuthenticationType()) : null;
        String method = raw != null ? raw : typed;
        if (method == null) {
            unverifiable(tally, line, "authStateJson.authMethod",
                    "the login method comes from the unsealed session context");
            return;
        }
        String head = SessionLineValues.loginMethodHead(method, typed,
                session != null ? session.getAuthenticationAssurance() : null);
        String value = line.entryLine().value();
        String details = value.contains("; ") ? value.substring(0, value.indexOf("; ")) : value;
        List<String> parts = Arrays.asList(details.split(", "));
        if (!head.equals(parts.get(0))) {
            if (raw == null) {
                // The render takes the method of the session context first, which the package does not keep.
                unverifiable(tally, line, "authStateJson.authMethod",
                        "the login method differs from the sealed session's type and may come from the unsealed "
                                + "session context");
                return;
            }
            mismatch(tally, line, head, parts.get(0), "authStateJson.authMethod",
                    "the login method is not the sealed one");
            return;
        }
        if (session != null && session.getMfaVerified() != null) {
            String mfa = SessionLineValues.mfaState(session.getMfaVerified());
            if (!parts.contains(mfa)) {
                mismatch(tally, line, mfa, details, CONTEXT + "session.mfaVerified",
                        "the MFA state is not the sealed one");
                return;
            }
        }
        tally.matched(line);
    }

    private static Instant instant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        }
        catch (DateTimeException exception) {
            return null;
        }
    }

    /** The dictionary's missing text of a line, or null when the line is left out without a value. */
    private static String missingText(PromptBlock block, String name) {
        return SecurityDecisionPromptDictionary.ENTRIES.stream()
                .filter(entry -> entry.block() == block && entry.name().equals(name))
                .findFirst().map(PromptDictionaryEntry::missingText).orElse(null);
    }

    /** The first value with text, trimmed; else the last value as given (the default). */
    private static String first(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return values.length > 0 ? values[values.length - 1] : null;
    }

    /**
     * The authorization effect and its policy up to the provenance in parentheses (the provenance comes from the
     * event's metadata, which the package does not keep), then the method outcome after authorization.
     */
    private static void authorizationEffect(PromptInspectionTally tally, InspectedPrompt.Line line,
                                            CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
        String effect = DecisionFactLineValues.authorizationEffect(authorization);
        String failure = DecisionFactLineValues.methodFailure(authorization);
        String value = line.entryLine().value();
        String source = CONTEXT + "authorization.authorizationEffect";
        if (effect == null && failure == null) {
            mismatch(tally, line, "no line (the sealed authorization states no effect)", value, source,
                    "the prompt states an authorization effect the sealed context does not hold");
            return;
        }
        List<String> parts = Arrays.asList(value.split("; "));
        if (effect != null) {
            String first = parts.get(0);
            boolean kept = first.equals(effect) || (first.startsWith(effect + " (") && first.endsWith(")"));
            if (!kept) {
                mismatch(tally, line, effect, first, source, "the authorization effect is not the sealed one");
                return;
            }
        }
        if (failure != null && !parts.contains(failure)) {
            mismatch(tally, line, failure, value, CONTEXT + "authorization.methodExecutionFailure",
                    "the method outcome after authorization is not the sealed one");
            return;
        }
        tally.matched(line);
    }

    /** The line says the expected value; without one the line should not be there. */
    private static void expected(PromptInspectionTally tally, InspectedPrompt.Line line, String expected, String source,
                                 String what) {
        if (line == null) {
            return;
        }
        if (expected == null) {
            mismatch(tally, line, "no line (the sealed context holds no " + what + ")", line.entryLine().value(), source,
                    "the prompt states a " + what + " the sealed context does not hold");
            return;
        }
        compare(tally, line, expected, line.entryLine().value(), source, "the " + what + " is not the sealed one");
    }


    private static void roles(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
        boolean effective = authorization != null && !authorization.getEffectiveRoles().isEmpty();
        List<String> sealed = effective ? authorization.getEffectiveRoles()
                : context.getActor() != null ? context.getActor().getRoleSet() : List.of();
        if (listedSame(tally, line, sealed, effective ? "authorization.effectiveRoles" : "actor.roleSet", "roles", ", ")) {
            // R1b-7 (P3 extra 35): the whole line, with the scope tags, the flow and the host source.
            whole(tally, line, CONTEXT + "authorization", "roles", List.of(), parts -> RequestLineValues.roles(context));
        }
    }

    private static void permissions(PromptInspectionTally tally, InspectedPrompt.Line line,
                                    CanonicalSecurityContext context) {
        CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
        boolean effective = authorization != null && !authorization.getEffectivePermissions().isEmpty();
        List<String> sealed = effective ? authorization.getEffectivePermissions()
                : context.getActor() != null ? context.getActor().getAuthoritySet() : List.of();
        if (listedSame(tally, line, sealed, effective ? "authorization.effectivePermissions" : "actor.authoritySet",
                "permissions", ", ")) {
            // R1b-7 (P3 extra 35): the whole line, with the host source.
            whole(tally, line, CONTEXT + "authorization", "permissions", List.of(),
                    parts -> RequestLineValues.permissions(context));
        }
    }

    private static void listed(PromptInspectionTally tally, InspectedPrompt.Line line, List<String> sealed, String field,
                               String what, String separator) {
        if (listedSame(tally, line, sealed, field, what, separator)) {
            tally.matched(line);
        }
    }

    /**
     * Whether a list line names the values of the sealed list as a set: {@code A, B; source ...} with the comma
     * separator, whose text after the first semicolon is not a value, or {@code A; B} with the semicolon separator. A
     * line that does not is pointed at.
     */
    private static boolean listedSame(PromptInspectionTally tally, InspectedPrompt.Line line, List<String> sealed,
                                      String field, String what, String separator) {
        if (line == null) {
            return false;
        }
        Set<String> expected = new TreeSet<>();
        sealed.stream().filter(value -> value != null && !value.isBlank()).map(String::trim).forEach(expected::add);
        String value = line.entryLine().value();
        int end = ", ".equals(separator) ? value.indexOf("; ") : -1;
        Set<String> actual = new TreeSet<>(Arrays.asList((end >= 0 ? value.substring(0, end) : value).split(separator)));
        if (expected.isEmpty()) {
            mismatch(tally, line, "no line (the sealed context holds no " + what + ")", value, CONTEXT + field,
                    "the prompt states " + what + " the sealed context does not hold");
            return false;
        }
        String expectedValues = String.join(", ", expected);
        String drawnValues = String.join(", ", actual);
        if (!expectedValues.equals(drawnValues)) {
            mismatch(tally, line, expectedValues, drawnValues, CONTEXT + field, "the " + what + " are not the sealed ones");
            return false;
        }
        return true;
    }

    private static void action(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        String value = line.entryLine().value();
        Matcher drawn = ACTION.matcher(value);
        if (!drawn.matches()) {
            mismatch(tally, line, "FAMILY (source) METHOD (template ...)", value, CONTEXT + "resource",
                    "the action line does not read as family, source, method and details");
            return;
        }
        CanonicalSecurityContext.Resource resource = context.getResource();
        String family = resource != null ? text(resource.getActionFamily()) : null;
        if (family == null) {
            unverifiable(tally, line, CONTEXT + "resource.actionFamily",
                    "the action family comes from the unsealed current request snapshot");
            return;
        }
        if (!family.equals(drawn.group(1))) {
            mismatch(tally, line, family, drawn.group(1), CONTEXT + "resource.actionFamily",
                    "the action family is not the sealed one");
            return;
        }
        String method = text(resource.getHttpMethod());
        if (method != null && !method.equals(drawn.group(2))) {
            mismatch(tally, line, method, drawn.group(2), CONTEXT + "resource.httpMethod",
                    "the method is not the sealed one");
            return;
        }
        String template = text(resource.getPathFamily());
        if (template != null && (drawn.group(3) == null || !drawn.group(3).contains("template " + template))) {
            mismatch(tally, line, "template " + template, drawn.group(3), CONTEXT + "resource.pathFamily",
                    "the path template is not the sealed one");
            return;
        }
        // R1b-7 (P3 extra 35): the whole line. The method and the protected method the render takes from the request's
        // metadata first are sealed as the request facts; without a sealed path template, the render's template may
        // come from a URL template the package does not seal.
        Map<String, Object> facts = tally.subject().sources().requestFacts();
        boolean factsKnown = factsKnown(tally);
        String path = text(resource.getRequestPath());
        String resourceMethod = RequestLineValues.qualifiedResourceMethod(resource);
        String[] sealed = {
                method != null ? method : factsKnown ? asText(facts.get("httpMethod")) : null,
                template != null ? template : factsKnown ? SecuritySemanticNormalizer.pathFamilyOf(facts,
                        firstText(path, asText(facts.get("requestPath")))) : null,
                RequestLineValues.protectedMethod(factsKnown
                        ? firstText(asText(facts.get("protectableMethod")), resourceMethod) : text(resourceMethod))};
        OpenPart[] parts = {
                method == null && !factsKnown ? new OpenPart(sealed[0], true,
                        PromptInspectionSources.REQUEST_FACTS + ".httpMethod", FACTS_NOT_KNOWN) : null,
                template == null ? new OpenPart(sealed[1], true, CONTEXT + "resource.pathFamily",
                        "without a sealed path template the render may take the request's URL template, which is not "
                                + "sealed") : null,
                !factsKnown ? new OpenPart(sealed[2], true, PromptInspectionSources.REQUEST_FACTS + ".protectableMethod",
                        FACTS_NOT_KNOWN) : null};
        List<OpenPart> open = Arrays.stream(parts).filter(Objects::nonNull).toList();
        whole(tally, line, CONTEXT + "resource", "action", open, values -> {
            String[] drawnParts = sealed.clone();
            int next = 0;
            for (int index = 0; index < parts.length; index++) {
                if (parts[index] != null) {
                    drawnParts[index] = values.get(next++);
                }
            }
            return RequestLineValues.action(family, resource.getActionFamilySource(), drawnParts[0], path, drawnParts[1],
                    drawnParts[2]);
        });
    }

    private static void target(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        CanonicalSecurityContext.Resource resource = context.getResource();
        if (resource == null) {
            mismatch(tally, line, "no line (the sealed context holds no resource)", line.entryLine().value(),
                    CONTEXT + "resource", "the prompt states a target the sealed context does not hold");
            return;
        }
        String head = RequestLineValues.targetHead(resource);
        String drawnHead = line.entryLine().value();
        String drawnCategory = null;
        int categoryAt = drawnHead.lastIndexOf(CATEGORY);
        if (categoryAt >= 0) {
            drawnCategory = drawnHead.substring(categoryAt + CATEGORY.length());
            drawnHead = drawnHead.substring(0, categoryAt);
        }
        String drawnLabel = null;
        int labelAt = drawnHead.indexOf(" (");
        if (labelAt >= 0 && drawnHead.endsWith(")")) {
            drawnLabel = drawnHead.substring(labelAt + 2, drawnHead.length() - 1);
            drawnHead = drawnHead.substring(0, labelAt);
        }
        if (!head.equals(drawnHead)) {
            mismatch(tally, line, head, drawnHead, CONTEXT + "resource.pathFamily",
                    "the target is not named by the sealed path template");
            return;
        }
        // N-INJ-3: the line says only where the business label is; its text is compared on its UNTRUSTED TEXT line.
        String label = RequestLineValues.targetLabel(resource);
        if (!Objects.equals(label, drawnLabel)) {
            mismatch(tally, line, label, drawnLabel, CONTEXT + "resource.businessLabel", label != null
                    ? "the target line does not say where the sealed business label is (an UNTRUSTED TEXT line)"
                    : "the target names a business label the sealed resource does not hold");
            return;
        }
        String category = text(resource.getResourceCategory());
        if (!Objects.equals(category, drawnCategory)) {
            mismatch(tally, line, category, drawnCategory, CONTEXT + "resource.resourceCategory",
                    "the target's category is not the sealed one");
            return;
        }
        tally.matched(line);
    }

    private static void device(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        String expected = RequestLineValues.sealedDeviceName(context.getDevice());
        if (expected == null) {
            unverifiable(tally, line, CONTEXT + "device",
                    "the device name comes from the unsealed current request snapshot or the requester's user agent");
            return;
        }
        String head = head(line.entryLine().value());
        if (!expected.equals(head)) {
            mismatch(tally, line, expected, head, CONTEXT + "device", "the device is not the sealed one");
            return;
        }
        // R1b-7 (P3 extra 35): the whole line. Whether the host declared the device new or known is not sealed.
        String seen = RequestLineValues.deviceSeen(false, context);
        List<OpenPart> open = Objects.equals(seen, RequestLineValues.deviceSeen(true, context)) ? List.of()
                : List.of(new OpenPart(seen, seen == null, CONTEXT + "session.newDevice",
                "whether the host declared the device new or known is not sealed"));
        whole(tally, line, CONTEXT + "device", "device", open,
                parts -> RequestLineValues.device(expected, open.isEmpty() ? seen : parts.get(0), context.getDevice()));
    }

    private static void subject(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        CanonicalSecurityContext.Actor actor = context.getActor();
        String userId = actor != null ? text(actor.getUserId()) : null;
        if (userId == null) {
            unverifiable(tally, line, CONTEXT + "actor.userId", "the subject's user id is not sealed");
            return;
        }
        String head = head(line.entryLine().value());
        if (!userId.equals(head)) {
            mismatch(tally, line, userId, head, CONTEXT + "actor.userId", "the subject is another user than the sealed one");
            return;
        }
        // R1b-7 (P3 extra 35): the whole line. Without a sealed request time the account age counts to the event time.
        Instant at = context.getRequestObservedAt();
        String account = RequestLineValues.accountAge(actor, at);
        List<OpenPart> open = at == null && RequestLineValues.accountCreatedKnown(actor)
                ? List.of(new OpenPart(null, false, CONTEXT + "requestObservedAt",
                "the account age counts to the event time the render falls back to, which is not kept"))
                : List.of();
        whole(tally, line, CONTEXT + "actor", "subject", open,
                parts -> RequestLineValues.subject(userId, open.isEmpty() ? account : parts.get(0), context));
    }

    private static void time(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        Instant at = context.getRequestObservedAt();
        if (at == null) {
            unverifiable(tally, line, CONTEXT + "requestObservedAt",
                    "the request time is not sealed (the event time the render falls back to is not kept)");
            return;
        }
        ZoneId zone = tally.subject().eventZone();
        if (zone == null) {
            unverifiable(tally, line, PromptInspectionSubject.EVENT_TIME_ZONE_REF, "the event time zone is not sealed");
            return;
        }
        compare(tally, line, RequestLineValues.clock(at, zone), line.entryLine().value(), CONTEXT + "requestObservedAt",
                "the time is not the sealed request time on the sealed event clock");
    }

    private static void size(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        String expected = RequestLineValues.size(context.getResource() != null ? context.getResource().getRequestedItems() : null);
        if (expected == null) {
            mismatch(tally, line, "no line (the sealed resource holds no requested size)", line.entryLine().value(),
                    CONTEXT + "resource.requestedItems", "the prompt states a size the sealed resource does not hold");
            return;
        }
        compare(tally, line, expected, line.entryLine().value(), CONTEXT + "resource.requestedItems",
                "the size is not the sealed requested size");
    }

    private static void resourceClass(PromptInspectionTally tally, InspectedPrompt.Line line,
                                      CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        String sealed = context.getResource() != null ? text(context.getResource().getResourceClass()) : null;
        if (sealed == null) {
            mismatch(tally, line, "no line (the sealed resource holds no class)", line.entryLine().value(),
                    CONTEXT + "resource.resourceClass", "the prompt states a class the sealed resource does not hold");
            return;
        }
        String head = head(line.entryLine().value());
        if (!sealed.equals(head)) {
            mismatch(tally, line, sealed, head, CONTEXT + "resource.resourceClass", "the resource class is not the sealed one");
            return;
        }
        // R1b-7 (P3 extra 35): the whole line, with the sensitivity and the flags.
        whole(tally, line, CONTEXT + "resource", "resource class", List.of(),
                parts -> RequestLineValues.resourceClass(context.getResource()));
    }

    private static void network(PromptInspectionTally tally, InspectedPrompt.Line line, CanonicalSecurityContext context) {
        if (line == null) {
            return;
        }
        String value = line.entryLine().value();
        String expectedAddress = RequestLineValues.address(context.getSession());
        if (!expectedAddress.equals(head(value))) {
            mismatch(tally, line, expectedAddress, head(value), CONTEXT + "session.clientIp",
                    "the network address is not the sealed client address");
            return;
        }
        String zone = context.getLocation() != null ? text(context.getLocation().getNetworkZone()) : null;
        if (zone != null && !value.contains("zone " + zone)) {
            mismatch(tally, line, "zone " + zone, value, CONTEXT + "location.networkZone",
                    "the network zone is not the sealed one");
            return;
        }
        // R1b-7 (P3 extra 35): the whole line. The band is the one of the request's source address, sealed as the
        // request facts' client address, or of the sealed band; without learning evidence the render draws the sealed
        // band as written, so a band other than the sealed sources give is left unchecked.
        CanonicalSecurityContext.Location location = context.getLocation();
        String ipBand = location != null ? text(location.getIpBand()) : null;
        boolean factsKnown = factsKnown(tally);
        String band = ipBand != null || factsKnown ? SecuritySemanticNormalizer.normalizeNetwork(factsKnown
                ? asText(tally.subject().sources().requestFacts().get("clientIp")) : null, ipBand) : null;
        whole(tally, line, CONTEXT + "location", "network", List.of(new OpenPart(band, true, CONTEXT + "location.ipBand",
                        "the band comes from the request's source address, or without learning evidence from the sealed "
                                + "band as written")),
                parts -> RequestLineValues.network(context.getSession(), parts.get(0), location));
    }

    /**
     * A part of a drawn line the render may take from a source the package does not seal: the value the sealed sources
     * give (null when they give none), whether the render may leave it out, and where and why it is not compared.
     */
    private record OpenPart(String sealed, boolean mayBeAbsent, String source, String reason) {
    }

    /**
     * R1b-7 (P3 extra 35): the whole drawn line is the line the render's value function draws from the sealed sources.
     * A part the render may take from an unsealed source is matched only by the value the sealed sources give; a line
     * that differs from the sealed one only there is left unchecked with why, never pointed at.
     */
    private static void whole(PromptInspectionTally tally, InspectedPrompt.Line line, String source, String what,
                              List<OpenPart> open, Function<List<String>, String> draw) {
        String drawn = line.entryLine().value();
        String expected = draw.apply(open.stream()
                .map(part -> part.sealed() != null || part.mayBeAbsent() ? part.sealed() : NOT_SEALED).toList());
        if (drawn.equals(expected)) {
            tally.matched(line);
            return;
        }
        for (List<String> form : forms(open)) {
            String text = form.contains(OPEN) ? draw.apply(form) : null;
            if (text != null && formPattern(text).matcher(drawn).matches()) {
                OpenPart part = open.get(form.indexOf(OPEN));
                unverifiable(tally, line, part.source(), part.reason());
                return;
            }
        }
        mismatch(tally, line, expected != null ? expected : "no line (the sealed sources draw no " + what + " line)",
                drawn, source, "the " + what + " line is not the one the sealed sources draw");
    }

    /**
     * Every way the open parts may be drawn, fewest unsealed parts first: each part as the sealed sources give it, as
     * any text taken from an unsealed source, or left out when the render may leave it out.
     */
    private static List<List<String>> forms(List<OpenPart> open) {
        List<List<String>> forms = new ArrayList<>();
        forms.add(new ArrayList<>());
        for (OpenPart part : open) {
            List<List<String>> next = new ArrayList<>();
            for (List<String> form : forms) {
                if (part.sealed() != null) {
                    next.add(with(form, part.sealed()));
                }
                next.add(with(form, OPEN));
                if (part.mayBeAbsent()) {
                    next.add(with(form, null));
                }
            }
            forms = next;
        }
        forms.sort(Comparator.comparingLong(form -> form.stream().filter(OPEN::equals).count()));
        return forms;
    }

    private static List<String> with(List<String> form, String value) {
        List<String> next = new ArrayList<>(form);
        next.add(value);
        return next;
    }

    /** A drawn line's form as a pattern: its text, with any text without a part separator where a part is open. */
    private static Pattern formPattern(String form) {
        StringBuilder pattern = new StringBuilder();
        String[] pieces = form.split(OPEN, -1);
        for (int index = 0; index < pieces.length; index++) {
            if (index > 0) {
                pattern.append("[^,();]+");
            }
            pattern.append(Pattern.quote(pieces[index]));
        }
        return Pattern.compile(pattern.toString());
    }

    /** Whether the package seals request facts that read: the request's metadata the render takes parts from. */
    private static boolean factsKnown(PromptInspectionTally tally) {
        String facts = tally.subject().evidencePackage().getRequestFactsJson();
        return facts != null && !facts.isBlank()
                && !tally.subject().unreadSources().contains(PromptInspectionSources.REQUEST_FACTS);
    }

    private static String firstText(String first, String second) {
        return text(first) != null ? text(first) : text(second);
    }

    private static void compare(PromptInspectionTally tally, InspectedPrompt.Line line, String expected, String actual,
                                String source, String reason) {
        if (expected.equals(actual)) {
            tally.matched(line);
            return;
        }
        mismatch(tally, line, expected, actual, source, reason);
    }

    private static void mismatch(PromptInspectionTally tally, InspectedPrompt.Line line, String expected, String actual,
                                 String source, String reason) {
        tally.mismatch(tally.mismatchFinding().block(line.block().title()).entry(line.entryLine().label())
                .factId(line.factId()).lineNumber(line.number()).expected(expected).actual(actual).sourceRef(source)
                .reason(reason).build());
    }

    private static void unverifiable(PromptInspectionTally tally, InspectedPrompt.Line line, String source,
                                     String reason) {
        tally.unverifiable(tally.unverifiableFinding().block(line.block().title()).entry(line.entryLine().label())
                .factId(line.factId()).lineNumber(line.number()).actual(line.entryLine().value()).sourceRef(source)
                .reason(reason).build());
    }

    /** The value before its parenthesised details ({@code alice} of {@code alice (HUMAN_USER, ...)}). */
    private static String head(String value) {
        int open = value.indexOf(" (");
        return open >= 0 ? value.substring(0, open) : value;
    }

    private static Map<String, InspectedPrompt.Line> lines(InspectedPrompt prompt, PromptBlock block) {
        Map<String, InspectedPrompt.Line> lines = new HashMap<>();
        for (InspectedPrompt.Line line : prompt.lines()) {
            if (line.kind() == InspectedPrompt.Kind.ENTRY && line.block() == block) {
                lines.putIfAbsent(line.entryLine().label(), line);
            }
        }
        return lines;
    }

    private static String text(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
