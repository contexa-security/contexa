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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.policy.CanonicalContextFieldPolicy;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptUnknownKind;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * W4-8 (S-28, VR-5): the checks of a v20 security decision on the facts its prompt was drawn from, one function for
 * the response checker and the prompt inspector. What a fact says is read from the canonical context the prompt was
 * drawn from, in the fields and with the null rules of the v20 values; whether the prompt states the fact, and the IDs
 * it gave, from the drawn prompt (block headers, entry labels, IDs). The boundaries are those of the v20 system text,
 * the reason code conditions those of dictionary 5.
 */
public final class SecurityDecisionFactChecks {

    public static final String REQUIRED_BLOCK = "REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH";
    public static final String BLOCK_WITHOUT_EVIDENCE = "BLOCK_WITHOUT_DECISIVE_EVIDENCE";
    public static final String REQUIRED_LOW_RISK = "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH";
    public static final String REQUIRED_COVERED_WORK = "REQUIRED_COVERED_WORK_BOUNDARY_ACTION_MISMATCH";
    public static final String REASON_CODE_MISMATCH = "REASON_CODE_MISMATCH";
    /** v1.0 (from v19): a reason that rests on past records of the same target while the prompt draws none. */
    public static final String FALSE_PAST_RECORD_CLAIM = "FALSE_AUTHORIZED_RAG_CLAIM";
    /** A drawn past record line: a PAST RECORDS record or a new record of a SECOND PASS, by its number. */
    private static final Pattern PAST_RECORD_LINE = Pattern.compile("PAST_RECORDS\\.PastRecord\\d+|SECOND_PASS\\.NewPastRecord\\d+");
    /** A reason that says past records of the same target, or the v19 sentence of them, support the request. */
    private static final Pattern SAME_TARGET_RECORD_CLAIM = Pattern.compile("relevant to the same resource"
            + "|\\b(past|earlier|previous|prior) (allowed )?(records?|requests?|rag)\\b[^.;]*\\bsame (resource|target)\\b"
            + "|\\bsame (resource|target)\\b[^.;]*\\b(past|earlier|previous|prior) (allowed )?(records?|requests?)\\b");

    /** The count from which FailedLogins and RecentRequests form the session or request-rate abuse category. */
    static final int ABUSE_COUNT = 100;

    private static final Pattern LINE_ID = Pattern.compile("^\\[([A-Z])([0-9]+)] ");
    private static final Pattern UNKNOWN_ID = Pattern.compile("\\[" + PromptUnknownKind.FACT_PREFIX
            + "([0-9]+)] ([A-Za-z][A-Za-z0-9]*)");
    private static final Pattern LABEL = Pattern.compile("[A-Za-z][A-Za-z0-9]*");
    private static final Set<String> HIGH_CLASSES = Set.of("SENSITIVE", "CRITICAL");
    private static final Set<String> LOW_CLASSES = Set.of("PUBLIC", "NORMAL");

    private SecurityDecisionFactChecks() {
    }

    /**
     * What a v20 prompt drew: the entries it states with a value ({@code DECISION_FACTS.PolicySatisfied}), the entry of
     * each line ID ({@code F3}) and the name of each ID its UNKNOWN line gives ({@code U2}).
     */
    public record DrawnPrompt(Set<String> stated, Map<String, String> lineIds, Map<String, String> unknownIds) {

        public DrawnPrompt {
            stated = Collections.unmodifiableSet(new LinkedHashSet<>(stated));
            lineIds = Collections.unmodifiableMap(new LinkedHashMap<>(lineIds));
            unknownIds = Collections.unmodifiableMap(new LinkedHashMap<>(unknownIds));
        }

        /** The v20 user prompt as the model got it; a prompt without block headers draws nothing. */
        public static DrawnPrompt of(String userPrompt) {
            Set<String> stated = new LinkedHashSet<>();
            Map<String, String> lineIds = new LinkedHashMap<>();
            Map<String, String> unknownIds = new LinkedHashMap<>();
            PromptBlock block = null;
            for (String raw : userPrompt == null ? new String[0] : userPrompt.split("\n")) {
                String line = raw.strip();
                if (PromptBlock.isHeaderLine(line)) {
                    block = PromptBlock.fromSectionKey(line).orElse(null);
                    continue;
                }
                if (block == null || line.isEmpty()) {
                    continue;
                }
                String id = null;
                Matcher prefix = LINE_ID.matcher(line);
                if (prefix.find()) {
                    id = prefix.group(1) + prefix.group(2);
                    line = line.substring(prefix.end());
                }
                int colon = line.indexOf(": ");
                if (colon <= 0 || !LABEL.matcher(line.substring(0, colon)).matches()) {
                    continue;
                }
                String entry = block.name() + "." + line.substring(0, colon);
                stated.add(entry);
                if (id != null) {
                    lineIds.putIfAbsent(id, entry);
                }
                if (block == PromptBlock.UNKNOWN && line.startsWith("Unknown: ")) {
                    Matcher named = UNKNOWN_ID.matcher(line);
                    while (named.find()) {
                        unknownIds.putIfAbsent(PromptUnknownKind.FACT_PREFIX + named.group(1), named.group(2));
                    }
                }
            }
            return new DrawnPrompt(stated, lineIds, unknownIds);
        }

        boolean states(PromptBlock block, String name) {
            return stated.contains(block.name() + "." + name);
        }
    }

    /** What one cited fact came to (dictionary 5): it holds, it does not, or the facts here cannot tell. */
    public enum Outcome {
        MATCH,
        MISMATCH,
        UNDECIDED
    }

    /** One reason code with the fact it cites, what it came to and why. */
    public record ReasonFinding(String code, String fact, Outcome outcome, String reason) {
    }

    /**
     * The first boundary of the decision rules the action breaks, in their order, or null: the required BLOCK boundary,
     * BLOCK without it or a verified signal (K36), the required low-risk boundary, the required covered-work boundary;
     * a verified signal is an anomaly, so neither of the last two holds beside it. The boundaries read the
     * given decision facts: the conclusions the decision rules state, which the context keeps beside the records its
     * prompt states.
     */
    public static String boundaryViolation(CanonicalSecurityContext context, DecisionFacts facts, DrawnPrompt prompt,
                                           String rawAction) {
        if (context == null || prompt == null) {
            return null;
        }
        String action = rawAction != null ? rawAction.trim().toUpperCase(Locale.ROOT) : "";
        Read read = new Read(context, facts, prompt);
        if (read.requiredBlock()) {
            return "BLOCK".equals(action) ? null : REQUIRED_BLOCK;
        }
        if ("BLOCK".equals(action)) {
            // K36 (decision D5): a signal the server itself confirmed, stated on the VerifiedSignal line, is decisive
            // evidence a BLOCK may rest on. It permits a BLOCK and does not ask for one: the verified signal boundary
            // part, when a version includes it, says when to choose BLOCK.
            return read.verifiedSignal() ? null : BLOCK_WITHOUT_EVIDENCE;
        }
        if (read.lowRisk()) {
            return "ALLOW".equals(action) ? null : REQUIRED_LOW_RISK;
        }
        if (read.coveredWork()) {
            return "ALLOW".equals(action) ? null : REQUIRED_COVERED_WORK;
        }
        return null;
    }

    /**
     * v1.0 (A16, from v19 FALSE_AUTHORIZED_RAG_CLAIM): a reason that rests on past records of the same target when the
     * prompt draws no past record line, or null.
     */
    public static String pastRecordClaimViolation(DrawnPrompt prompt, String rawReasoning) {
        if (prompt == null || rawReasoning == null) {
            return null;
        }
        // A numbered record line, not the state or counts lines whose names also begin with PastRecord.
        boolean drawn = prompt.stated().stream().anyMatch(entry -> PAST_RECORD_LINE.matcher(entry).matches());
        if (drawn) {
            return null;
        }
        String reason = rawReasoning.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        return SAME_TARGET_RECORD_CLAIM.matcher(reason).find() ? FALSE_PAST_RECORD_CLAIM : null;
    }

    /**
     * A claim of the reason the facts contradict, or null: MFA verified or not (the session's MFA on LoginMethod),
     * a low or high sensitivity (ResourceClass), a denied authorization (AuthorizationEffect ALLOW).
     */
    public static String claimViolation(CanonicalSecurityContext context, DrawnPrompt prompt, String rawReasoning) {
        if (context == null || prompt == null || rawReasoning == null) {
            return null;
        }
        String reasoning = rawReasoning.toLowerCase(Locale.ROOT);
        Read read = new Read(context, prompt);
        Boolean mfa = prompt.states(PromptBlock.SESSION, "LoginMethod") && context.getSession() != null
                ? context.getSession().getMfaVerified() : null;
        if (Boolean.FALSE.equals(mfa) && claimsMfaVerified(reasoning) && !claimsMfaUnverified(reasoning)) {
            return "FALSE_MFA_VERIFIED_CLAIM";
        }
        if (Boolean.TRUE.equals(mfa) && claimsMfaUnverified(reasoning)) {
            return "FALSE_MFA_UNVERIFIED_CLAIM";
        }
        String resourceClass = read.resourceClass();
        if (resourceClass != null && HIGH_CLASSES.contains(resourceClass) && claimsLowSensitivity(reasoning)) {
            return "FALSE_LOW_SENSITIVITY_CLAIM";
        }
        if (resourceClass != null && LOW_CLASSES.contains(resourceClass) && claimsHighSensitivity(reasoning)) {
            return "FALSE_HIGH_SENSITIVITY_CLAIM";
        }
        if ("ALLOW".equals(read.authorizationEffect()) && claimsAuthorizationDenied(reasoning)) {
            return "FALSE_AUTHORIZATION_DENIED_CLAIM";
        }
        return null;
    }

    /** The reason findings that do not hold, as a violation the corrective retry can name; null when none. */
    public static String reasonViolation(List<ReasonFinding> findings) {
        List<String> parts = findings.stream().filter(finding -> finding.outcome() == Outcome.MISMATCH)
                .map(finding -> finding.code() + " " + finding.fact() + " (" + finding.reason() + ")").toList();
        return parts.isEmpty() ? null : REASON_CODE_MISMATCH + ": " + String.join("; ", parts);
    }

    private static boolean anySignal(CanonicalSecurityContext.Intent intent) {
        return intent != null && (Boolean.TRUE.equals(intent.getBotUserAgent())
                || Boolean.TRUE.equals(intent.getTlsFingerprintAltered())
                || Boolean.TRUE.equals(intent.getAbnormalHeaderOrder())
                || Boolean.TRUE.equals(intent.getLanguageMismatch())
                || Boolean.TRUE.equals(intent.getMissingReferer())
                || Boolean.TRUE.equals(intent.getImpossibleTravel()));
    }

    private static boolean atLeast(Integer count, int minimum) {
        return count != null && count >= minimum;
    }

    /** The facts the boundaries read, on the stated lines only (a fact the UNKNOWN line names states nothing). */
    private record Read(CanonicalSecurityContext context, DecisionFacts facts, DrawnPrompt prompt) {

        Read(CanonicalSecurityContext context, DrawnPrompt prompt) {
            this(context, context != null ? context.getDecisionFacts() : null, prompt);
        }

        String authorizationEffect() {
            CanonicalSecurityContext.Authorization authorization = context.getAuthorization();
            return prompt.states(PromptBlock.DECISION_FACTS, "AuthorizationEffect") && authorization != null
                    && authorization.getAuthorizationEffect() != null
                    ? authorization.getAuthorizationEffect().trim().toUpperCase(Locale.ROOT) : null;
        }

        String resourceClass() {
            CanonicalSecurityContext.Resource resource = context.getResource();
            return prompt.states(PromptBlock.REQUEST, "ResourceClass") && resource != null
                    ? SecuritySemanticNormalizer.normalizeResourceClass(resource.getResourceClass()) : null;
        }

        private Optional<DecisionFact> fact(String name) {
            return facts != null && prompt.states(PromptBlock.DECISION_FACTS, name) ? facts.fact(name) : Optional.empty();
        }

        private boolean factHas(String name, String code) {
            return fact(name).map(found -> found.codes().contains(code)).orElse(false);
        }

        private CanonicalSecurityContext.Intent intent() {
            return prompt.states(PromptBlock.DECISION_FACTS, "ClientSignals") ? context.getIntent() : null;
        }

        boolean rateAbuse() {
            CanonicalSecurityContext.Session session = context.getSession();
            // W5-10 D5: the line states the engine's count of the user's requests in the last 60 minutes beside the
            // host's count; either at the abuse count forms the category, as the line reads.
            Integer lastHour = context.getSessionNarrativeProfile() != null
                    ? context.getSessionNarrativeProfile().getUserRequestsLastHour() : null;
            return session != null && prompt.states(PromptBlock.SESSION, "FailedLogins")
                    && prompt.states(PromptBlock.SESSION, "RecentRequests")
                    && atLeast(session.getFailedLoginAttempts(), ABUSE_COUNT)
                    && (atLeast(session.getRecentRequestCount(), ABUSE_COUNT) || atLeast(lastHour, ABUSE_COUNT));
        }

        boolean deviceMismatch() {
            return prompt.states(PromptBlock.REQUEST, "Device") && context.getDevice() != null
                    && Boolean.FALSE.equals(context.getDevice().getFingerprintMatch());
        }

        boolean automation() {
            // docs/agent A4-4: an agent is an automation client by nature; its client signals form no attack category.
            if (AgentLineValues.agent(context) != null) {
                return false;
            }
            CanonicalSecurityContext.Intent intent = intent();
            return intent != null && (Boolean.TRUE.equals(intent.getBotUserAgent())
                    || Boolean.TRUE.equals(intent.getTlsFingerprintAltered())
                    || Boolean.TRUE.equals(intent.getAbnormalHeaderOrder()));
        }

        boolean impossibleTravel() {
            boolean stated = prompt.states(PromptBlock.DECISION_FACTS, "ClientSignals")
                    || prompt.states(PromptBlock.DECISION_FACTS, "Movement");
            return stated && context.getIntent() != null && Boolean.TRUE.equals(context.getIntent().getImpossibleTravel());
        }

        /** N2: the stated TenantMatch line says the actor's tenant and the request's tenant differ. */
        boolean tenantsDiffer() {
            return prompt.states(PromptBlock.DECISION_FACTS, "TenantMatch")
                    && Boolean.TRUE.equals(V1LineValues.tenantsDiffer(context));
        }

        /**
         * The required BLOCK boundary as the decision rules state it: a negative authorization, a tenant conflict that
         * DataConflicts names or TenantMatch states (N2), or two corroborated attack categories.
         */
        boolean requiredBlock() {
            String effect = authorizationEffect();
            if ("BLOCK".equals(effect) || "DENY".equals(effect) || factHas("DataConflicts", "TENANT_CONFLICT")
                    || tenantsDiffer()) {
                return true;
            }
            int categories = (rateAbuse() ? 1 : 0) + (deviceMismatch() ? 1 : 0) + (automation() ? 1 : 0)
                    + (impossibleTravel() ? 1 : 0);
            return categories >= 2;
        }

        /**
         * K36: the prompt states the anomaly signal the server itself issued for the request (the VerifiedSignal line,
         * drawn only for the trusted verification source); a signal of any other source is a requester's claim.
         */
        boolean verifiedSignal() {
            return prompt.states(PromptBlock.DECISION_FACTS, "VerifiedSignal")
                    && V1LineValues.verifiedSignal(context.getIntent()) != null;
        }

        /** An anomaly, a contradiction, a denial or a threat a stated fact names (the boundaries' list). */
        boolean adverseOtherThanTheDifferences() {
            CanonicalSecurityContext.Session session = context.getSession();
            String effect = authorizationEffect();
            boolean provisionalScope = CanonicalContextFieldPolicy.hasProvisionalRoleScopeProfile(context);
            return "BLOCK".equals(effect) || "DENY".equals(effect)
                    || fact("SessionDeviceChange").isPresent() || fact("SessionNetworkChange").isPresent()
                    || anySignal(intent()) || impossibleTravel() || verifiedSignal()
                    || (factHas("RoleScope", "ROLE_SCOPE_OUTSIDE") && !provisionalScope)
                    || fact("DataConflicts").isPresent()
                    || prompt.states(PromptBlock.DECISION_FACTS, "BlockedUser")
                    || prompt.states(PromptBlock.SESSION, "RecentDenied")
                    || prompt.states(PromptBlock.DECISION_FACTS, "ThreatMatch")
                    || (session != null && prompt.states(PromptBlock.SESSION, "FailedLogins")
                        && atLeast(session.getFailedLoginAttempts(), 1))
                    || (session != null && prompt.states(PromptBlock.SESSION, "MfaFailures")
                        && atLeast(session.getRecentMfaFailureCount(), 1));
        }

        boolean unexplainedDifference() {
            return facts != null && prompt.states(PromptBlock.DECISION_FACTS, "DeviationsFromBaseline")
                    && !facts.unexplained().isEmpty();
        }

        Boolean policySatisfied() {
            return facts != null && prompt.states(PromptBlock.DECISION_FACTS, "PolicySatisfied")
                    ? facts.policy().satisfied() : null;
        }

        /** A policy the prompt states whose requirement PolicySatisfied does not state as met. */
        boolean unmetRequirement() {
            return prompt.states(PromptBlock.DECISION_FACTS, "Policy") && !Boolean.TRUE.equals(policySatisfied());
        }

        boolean lowRisk() {
            String resourceClass = resourceClass();
            return "ALLOW".equals(authorizationEffect()) && resourceClass != null && !HIGH_CLASSES.contains(resourceClass)
                    && !unexplainedDifference() && !adverseOtherThanTheDifferences() && !unmetRequirement();
        }

        boolean coveredWork() {
            return "ALLOW".equals(authorizationEffect()) && Boolean.TRUE.equals(policySatisfied())
                    && !unexplainedDifference() && !adverseOtherThanTheDifferences();
        }
    }

    public static boolean claimsMfaVerified(String reasoning) {
        return reasoning.contains("mfa is verified")
                || reasoning.contains("mfa verified")
                || reasoning.contains("mfaverified=true")
                || reasoning.contains("mfaverified = true");
    }

    public static boolean claimsMfaUnverified(String reasoning) {
        return reasoning.contains("mfa is not verified")
                || reasoning.contains("mfa not verified")
                || reasoning.contains("mfa unverified")
                || reasoning.contains("mfaverified=false")
                || reasoning.contains("mfaverified = false");
    }

    public static boolean claimsLowSensitivity(String reasoning) {
        return reasoning.contains("low sensitivity")
                || reasoning.contains("low-resource sensitivity")
                || reasoning.contains("non-high sensitivity");
    }

    public static boolean claimsHighSensitivity(String reasoning) {
        if (reasoning.contains("not high sensitivity")
                || reasoning.contains("non-high sensitivity")) {
            return false;
        }
        return reasoning.contains("high sensitivity")
                || reasoning.contains("high-sensitivity")
                || reasoning.contains("critical sensitivity");
    }

    public static boolean claimsAuthorizationDenied(String reasoning) {
        return reasoning.contains("authorization denied")
                || reasoning.contains("authorization is denied")
                || reasoning.contains("authorizationeffect=deny")
                || reasoning.contains("authorizationeffect = deny");
    }
}
