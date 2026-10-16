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
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import io.contexa.contexacore.autonomous.context.decision.PolicyReason;
import io.contexa.contexacore.autonomous.context.policy.CanonicalContextFieldPolicy;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.context.prompt.PromptUnknownKind;
import io.contexa.contexacore.autonomous.context.support.SecuritySemanticNormalizer;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;

import java.util.ArrayList;
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
     * The first boundary of the v20 system text the action breaks, in the text's order, or null: the required BLOCK
     * boundary, BLOCK without it, the required low-risk boundary, the required covered-work boundary.
     */
    public static String boundaryViolation(CanonicalSecurityContext context, DrawnPrompt prompt, String rawAction) {
        if (context == null || prompt == null) {
            return null;
        }
        String action = rawAction != null ? rawAction.trim().toUpperCase(Locale.ROOT) : "";
        Read read = new Read(context, prompt);
        if (read.requiredBlock()) {
            return "BLOCK".equals(action) ? null : REQUIRED_BLOCK;
        }
        if ("BLOCK".equals(action)) {
            return BLOCK_WITHOUT_EVIDENCE;
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

    /**
     * Each reason code with the fact it cites (dictionary 5): the ID is in the prompt, its line is one the code cites
     * (a fact the UNKNOWN line names is cited by MATERIAL_MISSING_EVIDENCE and by a code that cites that fact), and the
     * code's condition holds on the facts. A condition whose facts the canonical context does not hold is UNDECIDED.
     */
    public static List<ReasonFinding> reasonFindings(CanonicalSecurityContext context,
                                                     MinimumActionRules.Settings settings, DrawnPrompt prompt,
                                                     List<SecurityDecisionOutputContract.Citation> citations) {
        List<ReasonFinding> findings = new ArrayList<>();
        if (prompt == null || citations == null) {
            return findings;
        }
        Map<String, SecurityDecisionOutputContract.ReasonCode> codes = new LinkedHashMap<>();
        SecurityDecisionOutputContract.REASON_CODES.forEach(code -> codes.put(code.code(), code));
        for (SecurityDecisionOutputContract.Citation citation : citations) {
            if (citation == null || citation.code() == null) {
                continue;
            }
            String fact = citation.fact() != null ? citation.fact().trim().toUpperCase(Locale.ROOT) : "";
            findings.add(finding(context, settings, prompt, codes.get(citation.code()), citation.code(), fact));
        }
        return findings;
    }

    /** The reason findings that do not hold, as a violation the corrective retry can name; null when none. */
    public static String reasonViolation(List<ReasonFinding> findings) {
        List<String> parts = findings.stream().filter(finding -> finding.outcome() == Outcome.MISMATCH)
                .map(finding -> finding.code() + " " + finding.fact() + " (" + finding.reason() + ")").toList();
        return parts.isEmpty() ? null : REASON_CODE_MISMATCH + ": " + String.join("; ", parts);
    }

    private static ReasonFinding finding(CanonicalSecurityContext context, MinimumActionRules.Settings settings,
                                         DrawnPrompt prompt, SecurityDecisionOutputContract.ReasonCode code,
                                         String name, String fact) {
        if (code == null) {
            return new ReasonFinding(name, fact, Outcome.MISMATCH, "not a reason code of the output contract");
        }
        String unknown = prompt.unknownIds().get(fact);
        String entry = prompt.lineIds().get(fact);
        if (unknown == null && entry == null) {
            return new ReasonFinding(name, fact, Outcome.MISMATCH, "the prompt gives no fact this ID");
        }
        if (unknown != null) {
            boolean cited = "MATERIAL_MISSING_EVIDENCE".equals(name)
                    || code.citedFacts().stream().anyMatch(cite -> nameOf(cite).equals(unknown));
            return cited ? new ReasonFinding(name, fact, Outcome.MATCH, "the UNKNOWN line names " + unknown)
                    : new ReasonFinding(name, fact, Outcome.MISMATCH, "the code does not cite " + unknown);
        }
        if (code.citedFacts().stream().noneMatch(cite -> cites(cite, entry))) {
            return new ReasonFinding(name, fact, Outcome.MISMATCH, "the code does not cite " + entry);
        }
        Boolean holds = context == null ? null : condition(context, settings, name, entry);
        if (holds == null) {
            return new ReasonFinding(name, fact, Outcome.UNDECIDED, undecided(name, settings));
        }
        return holds ? new ReasonFinding(name, fact, Outcome.MATCH, entry)
                : new ReasonFinding(name, fact, Outcome.MISMATCH, "the condition of " + name + " does not hold");
    }

    /** Why a code's condition cannot be decided: the rule settings a sealed package does not keep, or the facts. */
    private static String undecided(String code, MinimumActionRules.Settings settings) {
        if (code.startsWith("MIN_P") && settings == null) {
            return "the minimum action settings are not sealed, so the condition of " + code + " cannot be decided";
        }
        return "the condition of " + code + " cannot be decided on the facts here";
    }

    /** Whether a cited entry of the contract ({@code PAST_RECORDS.PastRecord{i}}) names a drawn entry. */
    private static boolean cites(String cite, String entry) {
        if (!cite.endsWith("{i}")) {
            return cite.equals(entry);
        }
        String stem = cite.substring(0, cite.length() - "{i}".length());
        return entry.startsWith(stem) && entry.length() > stem.length()
                && entry.substring(stem.length()).chars().allMatch(Character::isDigit);
    }

    private static String nameOf(String cite) {
        String name = cite.substring(cite.indexOf('.') + 1);
        return name.endsWith("{i}") ? name.substring(0, name.length() - "{i}".length()) : name;
    }

    /** Dictionary 5, the condition column; null when the canonical context does not hold the facts it needs. */
    private static Boolean condition(CanonicalSecurityContext context, MinimumActionRules.Settings settings,
                                     String code, String entry) {
        DecisionFacts facts = context.getDecisionFacts();
        CanonicalSecurityContext.Session session = context.getSession();
        CanonicalSecurityContext.RoleScopeProfile scope = context.getRoleScopeProfile();
        if (code.startsWith("MIN_P")) {
            // The rules are the host's settings: a sealed package does not keep them, the response checker does.
            if (facts == null || settings == null) {
                return null;
            }
            CanonicalSecurityContext.Resource resource = context.getResource();
            return MinimumActionRules.evaluate(facts, resource != null ? resource.getResourceClass() : null,
                            resource != null ? resource.getActionFamily() : null, settings).stream()
                    .anyMatch(hit -> hit.rule().code().equals(code));
        }
        if (code.equals("POLICY_UNKNOWN")) {
            // Valid when the UNKNOWN line names the policy (its U ID); a drawn Policy line is a known policy.
            return facts == null ? null : facts.unknown().contains("Policy");
        }
        if (code.equals("POLICY_SATISFIED")) {
            return facts == null ? null : Boolean.TRUE.equals(facts.policy().satisfied());
        }
        if (code.startsWith("POLICY_NOT_SATISFIED_")) {
            if (facts == null) {
                return null;
            }
            PolicyReason reason = facts.policy().reason();
            return Boolean.FALSE.equals(facts.policy().satisfied()) && reason != null && reason.code().equals(code);
        }
        switch (code) {
            case "BREAK_GLASS":
                return context.getFrictionProfile() != null && Boolean.TRUE.equals(context.getFrictionProfile().getBreakGlass());
            case "RECENT_PERMISSION_CHANGE":
                return scope != null && scope.getRecentPermissionChanges() != null
                        && !scope.getRecentPermissionChanges().isEmpty();
            case "TEMPORARY_ELEVATION":
                return scope != null && Boolean.TRUE.equals(scope.getTemporaryElevation());
            case "DELEGATION_SCOPE_DRIFT":
                return context.getDelegation() != null && Boolean.TRUE.equals(context.getDelegation().getObjectiveDrift());
            case "PRIOR_CHALLENGE_IN_SESSION":
                return priorNonAllow(context);
            case "CHALLENGE_VERIFIED_IN_SESSION":
                return session != null && session.getChallengeVerifiedAt() != null
                        && !session.getChallengeVerifiedAt().isBlank();
            case "FAILED_LOGINS":
                return session != null && atLeast(session.getFailedLoginAttempts(), 1);
            case "MFA_FAILURES":
                return session != null && atLeast(session.getRecentMfaFailureCount(), 1);
            case "CLIENT_SIGNAL_TAMPERING":
                return anySignal(context.getIntent());
            case "TENANT_CONFLICT", "AUTHORIZATION_CONFLICT", "DATA_CONFLICT":
                // Whichever line it cites, a conflict code holds when the data conflicts name that conflict.
                return facts == null ? null : facts.fact(DecisionFactNames.DATA_CONFLICTS)
                        .map(found -> found.codes().contains(code)).orElse(false);
            case "MATERIAL_CONTRADICTION":
                return facts == null ? null : facts.fact(DecisionFactNames.DATA_CONFLICTS).isPresent();
            case "BASELINE_NOT_ESTABLISHED", "PAST_RECORD_SAME_TARGET", "PAST_DENIED_SAME_ACTION",
                 "VALIDATED_CASE_MATCH", "THREAT_MATCH", "MATERIAL_MISSING_EVIDENCE":
                // Their facts (the baseline state, past records, threat knowledge) are not in the canonical context.
                return null;
            default:
                // The resolver puts the code on the fact that holds it (W4-8 (5): its codes are the contract's).
                if (facts == null) {
                    return null;
                }
                String name = entry.substring(entry.indexOf('.') + 1);
                Optional<DecisionFact> cited = facts.fact(name);
                if (cited.isEmpty() && entry.startsWith(PromptBlock.SESSION.name() + ".")) {
                    cited = facts.fact(DecisionFactNames.REPEAT_IN_SESSION);
                }
                return cited.map(found -> found.codes().contains(code)).orElse(false);
        }
    }

    private static boolean priorNonAllow(CanonicalSecurityContext context) {
        CanonicalSecurityContext.SessionNarrativeProfile narrative = context.getSessionNarrativeProfile();
        List<SessionDecisionRecord> decisions = narrative != null ? narrative.getSessionDecisions() : null;
        return decisions != null && decisions.stream().anyMatch(decision -> decision != null && decision.outcome() != null
                && !"ALLOW".equalsIgnoreCase(decision.outcome().trim()));
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

    /** The decision fact names the checks read (the dictionary's DECISION FACTS entries). */
    private static final class DecisionFactNames {
        static final String DATA_CONFLICTS = "DataConflicts";
        static final String REPEAT_IN_SESSION = "RepeatInSession";
    }

    /** The facts the boundaries read, on the stated lines only (a fact the UNKNOWN line names states nothing). */
    private record Read(CanonicalSecurityContext context, DrawnPrompt prompt) {

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
            DecisionFacts facts = context.getDecisionFacts();
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

        boolean requiredBlock() {
            String effect = authorizationEffect();
            if ("BLOCK".equals(effect) || "DENY".equals(effect) || factHas("DataConflicts", "TENANT_CONFLICT")) {
                return true;
            }
            int categories = (rateAbuse() ? 1 : 0) + (deviceMismatch() ? 1 : 0) + (automation() ? 1 : 0)
                    + (impossibleTravel() ? 1 : 0);
            return categories >= 2;
        }

        /** An anomaly, a contradiction, a denial or a threat a stated fact names (the boundaries' list). */
        boolean adverseOtherThanTheDifferences() {
            CanonicalSecurityContext.Session session = context.getSession();
            String effect = authorizationEffect();
            boolean provisionalScope = CanonicalContextFieldPolicy.hasProvisionalRoleScopeProfile(context);
            return "BLOCK".equals(effect) || "DENY".equals(effect)
                    || fact("SessionDeviceChange").isPresent() || fact("SessionNetworkChange").isPresent()
                    || anySignal(intent()) || impossibleTravel()
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
            DecisionFacts facts = context.getDecisionFacts();
            return facts != null && prompt.states(PromptBlock.DECISION_FACTS, "DeviationsFromBaseline")
                    && !facts.unexplained().isEmpty();
        }

        Boolean policySatisfied() {
            DecisionFacts facts = context.getDecisionFacts();
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
