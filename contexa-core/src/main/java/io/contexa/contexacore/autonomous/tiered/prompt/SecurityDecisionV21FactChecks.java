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

import io.contexa.contexacommon.domain.EventTimeZone;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.CompanyRecordsEvaluator;
import io.contexa.contexacore.autonomous.context.decision.DecisionFact;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import io.contexa.contexacore.autonomous.context.decision.PolicyReason;
import io.contexa.contexacore.autonomous.context.decision.RecordCheck;
import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import io.contexa.contexacore.autonomous.store.SessionDecisionRecord;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.DrawnPrompt;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.Outcome;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.ReasonFinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The checks of a v21 security decision (V-5): whether what the model says is what the prompt's lines state. They never
 * look at the action. A reason code cites a line the prompt drew, of an entry the code may cite; a code that names a
 * fact the core measured holds only when the core measured it so (a time not among the usual ones, a record decided
 * after the request); a code that names the model's own judgment of a record or of the data holds on any line it may
 * cite. An explanation the model weighed cites lines the prompt drew.
 */
public final class SecurityDecisionV21FactChecks {

    public static final String HYPOTHESES_MISSING = "HYPOTHESES_MISSING";
    public static final String HYPOTHESIS_MISMATCH = "HYPOTHESIS_MISMATCH";
    public static final String REASON_CODES_MISSING = "REASON_CODES_MISSING";

    /** The finding reason of a code the output contract does not have: the answer made the code up. */
    static final String NOT_A_CODE = "not a reason code of the output contract";
    /** The finding reason of a fact ID the prompt does not give: the answer made the line up. */
    static final String NO_SUCH_FACT = "the prompt gives no fact this ID";

    /** The codes that name the model's judgment of the lines they cite; the lines alone cannot fail them. */
    static final Set<String> JUDGMENT_CODES = Set.of("RECORD_COVERS_WORK", "RECORD_OTHER_TARGET", "NO_COVERING_RECORD",
            "TRAVEL_EXPLAINS_NETWORK", "DATA_NATURE_MISMATCH", "SESSION_SEQUENCE", "DELEGATION_OBJECTIVE_EXCEEDED");

    /** The record codes the core measures exactly, with the failure of the record check that measures them. */
    private static final Map<String, PolicyReason> MEASURED_RECORD_CODES = Map.of(
            "RECORD_DECIDED_AFTER_REQUEST", PolicyReason.LATE,
            "RECORD_OUTSIDE_PERIOD", PolicyReason.EXPIRED,
            "RECORD_OVER_LIMIT", PolicyReason.OVER_LIMIT,
            "RECORD_CUMULATIVE_OVER_LIMIT", PolicyReason.CUMULATIVE);

    private SecurityDecisionV21FactChecks() {
    }

    /** One explanation the model weighed: its id, the name it gave H5, its assessment and the fact ids for and against. */
    public record Hypothesis(String id, String name, String assessment, List<String> supporting, List<String> against) {

        public Hypothesis {
            supporting = supporting == null ? List.of() : List.copyOf(supporting);
            against = against == null ? List.of() : List.copyOf(against);
        }
    }

    /**
     * Each reason code with the fact it cites: the ID is in the prompt, its line is one the code may cite, and a code
     * that names a measured fact holds on the facts the prompt was drawn from. A judgment code holds on its line.
     */
    public static List<ReasonFinding> reasonFindings(CanonicalSecurityContext context, DrawnPrompt prompt,
                                                     List<SecurityDecisionOutputContract.Citation> citations) {
        List<ReasonFinding> findings = new ArrayList<>();
        if (prompt == null || citations == null) {
            return findings;
        }
        for (SecurityDecisionOutputContract.Citation citation : citations) {
            if (citation == null || citation.code() == null) {
                continue;
            }
            String fact = citation.fact() != null ? citation.fact().trim().toUpperCase(Locale.ROOT) : "";
            findings.add(finding(context, prompt, citation.code(), fact));
        }
        return findings;
    }

    /**
     * Whether a finding that does not hold is one of the answer's own making: a code the contract does not have or a
     * line the prompt does not give. Any other finding that does not hold is a disagreement about a line that exists
     * (the code may not cite that entry, or the measured fact does not state what the code says).
     */
    public static boolean madeUp(ReasonFinding finding) {
        return finding.outcome() == Outcome.MISMATCH
                && (NOT_A_CODE.equals(finding.reason()) || NO_SUCH_FACT.equals(finding.reason()));
    }

    /**
     * What is wrong with the explanations the model weighed, or null: none given, an id or an assessment the contract
     * does not have, or a fact id the prompt does not give.
     */
    public static String hypothesisViolation(DrawnPrompt prompt, List<Hypothesis> hypotheses) {
        if (hypotheses == null || hypotheses.isEmpty()) {
            return HYPOTHESES_MISSING;
        }
        List<String> parts = new ArrayList<>();
        for (Hypothesis hypothesis : hypotheses) {
            String id = hypothesis.id() != null ? hypothesis.id().trim().toUpperCase(Locale.ROOT) : "";
            if (!SecurityDecisionOutputContractV4.HYPOTHESES.contains(id)) {
                parts.add(id + " (not an explanation of the output contract)");
                continue;
            }
            String assessment = hypothesis.assessment() != null
                    ? hypothesis.assessment().trim().toUpperCase(Locale.ROOT) : "";
            if (!SecurityDecisionOutputContractV4.ASSESSMENTS.contains(assessment)) {
                parts.add(id + " (no assessment of the output contract)");
            }
            List<String> missing = new ArrayList<>();
            List<String> cited = new ArrayList<>(hypothesis.supporting());
            cited.addAll(hypothesis.against());
            for (String fact : cited) {
                String factId = fact != null ? fact.trim().toUpperCase(Locale.ROOT) : "";
                if (!prompt.lineIds().containsKey(factId) && !prompt.unknownIds().containsKey(factId)
                        && !missing.contains(factId)) {
                    missing.add(factId);
                }
            }
            if (!missing.isEmpty()) {
                parts.add(id + " (the prompt gives no fact " + String.join(", ", missing) + ")");
            }
        }
        return parts.isEmpty() ? null : HYPOTHESIS_MISMATCH + ": " + String.join("; ", parts);
    }

    private static ReasonFinding finding(CanonicalSecurityContext context, DrawnPrompt prompt, String name,
                                         String fact) {
        Optional<SecurityDecisionOutputContractV4.ReasonCode> found = SecurityDecisionOutputContractV4.find(name);
        if (found.isEmpty()) {
            return new ReasonFinding(name, fact, Outcome.MISMATCH, NOT_A_CODE);
        }
        SecurityDecisionOutputContractV4.ReasonCode code = found.get();
        String unknown = prompt.unknownIds().get(fact);
        String entry = prompt.lineIds().get(fact);
        if (unknown == null && entry == null) {
            return new ReasonFinding(name, fact, Outcome.MISMATCH, NO_SUCH_FACT);
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
        if (JUDGMENT_CODES.contains(name)) {
            return new ReasonFinding(name, fact, Outcome.MATCH, entry + " (the model's judgment of the line)");
        }
        Boolean holds = context == null ? null : condition(context, name, entry);
        if (holds == null) {
            return new ReasonFinding(name, fact, Outcome.UNDECIDED,
                    "the condition of " + name + " cannot be decided on the facts here");
        }
        return holds ? new ReasonFinding(name, fact, Outcome.MATCH, entry)
                : new ReasonFinding(name, fact, Outcome.MISMATCH, "the line does not state what " + name + " says");
    }

    /** Whether the facts the prompt was drawn from state what the code says; null when they cannot tell. */
    private static Boolean condition(CanonicalSecurityContext context, String code, String entry) {
        DecisionFacts facts = context.getDecisionFacts();
        CanonicalSecurityContext.Session session = context.getSession();
        CanonicalSecurityContext.RoleScopeProfile scope = context.getRoleScopeProfile();
        PolicyReason measured = MEASURED_RECORD_CODES.get(code);
        if (measured != null) {
            return recordFails(context, entry, measured);
        }
        switch (code) {
            case "POLICY_NOT_KNOWN":
                return facts == null ? null : facts.unknown().contains("Policy");
            case "ROLE_SCOPE_OUTSIDE":
                // Whether the group's lists hold the request, read the way the v20 facts read the same lists.
                return DecisionFactsResolver.resolve(context, null, EventTimeZone.get())
                        .fact("RoleScope").map(found -> found.codes().contains(code)).orElse(false);
            case "BREAK_GLASS":
                return context.getFrictionProfile() != null
                        && Boolean.TRUE.equals(context.getFrictionProfile().getBreakGlass());
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
                return session != null && atLeastOne(session.getFailedLoginAttempts());
            case "MFA_FAILURES":
                return session != null && atLeastOne(session.getRecentMfaFailureCount());
            case "CLIENT_SIGNAL_TAMPERING":
                return anySignal(context.getIntent());
            case "TENANT_CONFLICT", "AUTHORIZATION_CONFLICT", "DATA_CONFLICT":
                return facts == null ? null : facts.fact("DataConflicts")
                        .map(found -> found.codes().contains(code)).orElse(false);
            case "MATERIAL_CONTRADICTION", "BASELINE_NOT_ESTABLISHED", "PAST_RECORD_SAME_TARGET",
                 "PAST_DENIED_SAME_ACTION", "VALIDATED_CASE_MATCH", "THREAT_MATCH", "MATERIAL_MISSING_EVIDENCE":
                // A contradiction is the model's reading; the other facts (the baseline state, past records, threat
                // knowledge) are not in the canonical context.
                return null;
            default:
                // A measured fact's code is on the fact the records notation states it with (DEVIATION_*,
                // BASELINE_MATCH, ASSIGNED_TARGET, ON_CALL, TICKET_CLAIM_FALSE, REPEAT_IN_SESSION, the changes).
                if (facts == null) {
                    return null;
                }
                String name = entry.substring(entry.indexOf('.') + 1);
                Optional<DecisionFact> cited = facts.fact(name);
                if (cited.isEmpty() && entry.startsWith(PromptBlock.SESSION.name() + ".")) {
                    cited = facts.fact("RepeatInSession");
                }
                return cited.map(found -> found.codes().contains(code)).orElse(false);
        }
    }

    /**
     * Whether a record of the cited kind fails the request for that reason, as the core checks the records at the
     * request time; null without the records.
     */
    private static Boolean recordFails(CanonicalSecurityContext context, String entry, PolicyReason reason) {
        if (context.getFrictionProfile() == null) {
            return null;
        }
        List<SessionDecisionRecord> decisions = context.getSessionNarrativeProfile() != null
                && context.getSessionNarrativeProfile().getSessionDecisions() != null
                ? context.getSessionNarrativeProfile().getSessionDecisions() : List.of();
        CompanyRecordsEvaluator.Evaluation evaluation = CompanyRecordsEvaluator.evaluate(context.getFrictionProfile(),
                CompanyRecordsEvaluator.Request.of(context, decisions), EventTimeZone.get());
        List<RecordCheck> checks = entry.endsWith(".Ticket") ? evaluation.tickets() : evaluation.approvals();
        return checks.stream().anyMatch(check -> check.failures().contains(reason));
    }

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

    private static boolean priorNonAllow(CanonicalSecurityContext context) {
        CanonicalSecurityContext.SessionNarrativeProfile narrative = context.getSessionNarrativeProfile();
        return narrative != null && narrative.getSessionDecisions() != null
                && narrative.getSessionDecisions().stream().anyMatch(decision -> decision != null
                && decision.outcome() != null && !"ALLOW".equalsIgnoreCase(decision.outcome().trim()));
    }

    private static boolean anySignal(CanonicalSecurityContext.Intent intent) {
        return intent != null && (Boolean.TRUE.equals(intent.getBotUserAgent())
                || Boolean.TRUE.equals(intent.getTlsFingerprintAltered())
                || Boolean.TRUE.equals(intent.getAbnormalHeaderOrder())
                || Boolean.TRUE.equals(intent.getLanguageMismatch())
                || Boolean.TRUE.equals(intent.getMissingReferer())
                || Boolean.TRUE.equals(intent.getImpossibleTravel()));
    }

    private static boolean atLeastOne(Integer count) {
        return count != null && count >= 1;
    }
}
