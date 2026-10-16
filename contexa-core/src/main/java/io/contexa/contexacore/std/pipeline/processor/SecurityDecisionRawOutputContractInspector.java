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
package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.decision.DecisionFacts;
import io.contexa.contexacore.autonomous.context.decision.MinimumActionRules;
import java.util.stream.Collectors;
import java.util.List;
import org.springframework.ai.chat.prompt.Prompt;

import static io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.claimsAuthorizationDenied;
import static io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.claimsHighSensitivity;
import static io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.claimsLowSensitivity;
import static io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.claimsMfaUnverified;
import static io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks.claimsMfaVerified;

/**
 * Inspects a raw security-decision response without mutating the live pipeline context.
 */
public final class SecurityDecisionRawOutputContractInspector {

    /** N-OUT-1 (G1-1): the pipeline metadata key of the fallback of a contract violation left after the retry. */
    public static final String CONTRACT_FALLBACK_ACTION = "securityDecisionContractFallbackAction";

    /**
     * N-OUT-1 (G1-1, decision A): the fallback of a contract violation left after the corrective retry. It is ESCALATE
     * (decision A: the code does not choose the response) unless the broken rule asks for one action ESCALATE does not
     * give: a boundary that requires BLOCK gives BLOCK, the low risk boundary that requires ALLOW gives ALLOW.
     */
    public static String fallbackActionFor(String violation) {
        if ("REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH".equals(violation)) {
            return "BLOCK";
        }
        if ("REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH".equals(violation)
                || SecurityDecisionFactChecks.REQUIRED_COVERED_WORK.equals(violation)) {
            return "ALLOW";
        }
        return "ESCALATE";
    }

    private final SecurityDecisionOutputParser outputParser = new SecurityDecisionOutputParser();

    /**
     * W4-5 (plan 7, dictionary 6): the inspection with the minimum action rules when the check is given (enforce mode):
     * an answer weaker than a rule that applies is a violation naming the rule and the action it asks for. A parse
     * failure or another violation comes first.
     */
    public Inspection inspect(String rawResponse, Prompt prompt, String requestId, String attempt,
                              MinimumActionCheck check) {
        return withMinimumActionRules(inspect(rawResponse, prompt, requestId, attempt), check);
    }

    private Inspection withMinimumActionRules(Inspection inspection, MinimumActionCheck check) {
        if (check == null || inspection.requiresRetry() || inspection.response() == null) {
            return inspection;
        }
        List<MinimumActionRules.Hit> hits = MinimumActionRules.evaluate(check.facts(), check.resourceClass(),
                check.actionFamily(), check.settings());
        if (!MinimumActionRules.violatedBy(inspection.response().getAction(), hits)) {
            return inspection;
        }
        String violation = "MINIMUM_ACTION_VIOLATION: " + hits.stream()
                .map(hit -> hit.rule().code() + " requires " + hit.requiredAction() + " or a stronger action")
                .collect(Collectors.joining("; "));
        return new Inspection(inspection.response(), inspection.parsingFallback(), inspection.parseFailureCategory(),
                inspection.rawOutputHash(), inspection.rawOutputLength(), violation, violation);
    }

    /** W4-8: the inputs of the v20 checks: the canonical context the prompt was drawn from, its user prompt, the rules. */
    public record V20Check(CanonicalSecurityContext context, String userPrompt, MinimumActionRules.Settings settings) {
    }

    /**
     * W4-8 (S-28): a v20 decision is inspected on the facts its prompt was drawn from (SecurityDecisionFactChecks): the
     * reason claims, the boundaries of the v20 system text and the reason codes of dictionary 5, then the minimum action
     * rules when given. The v19 label checks read the prompt text and run on a v19 prompt only (plan 9).
     */
    public Inspection inspect(String rawResponse, Prompt prompt, String requestId, String attempt,
                              MinimumActionCheck check, V20Check v20) {
        if (v20 == null || v20.context() == null) {
            return inspect(rawResponse, prompt, requestId, attempt, check);
        }
        SecurityDecisionFactChecks.DrawnPrompt drawn = SecurityDecisionFactChecks.DrawnPrompt.of(v20.userPrompt());
        return withMinimumActionRules(inspect(rawResponse, requestId, attempt, parsed -> v20Violation(v20, drawn, parsed)),
                check);
    }

    private static String v20Violation(V20Check v20, SecurityDecisionFactChecks.DrawnPrompt drawn,
                                       SecurityDecisionResponseLite response) {
        if (response == null) {
            return null;
        }
        String claim = SecurityDecisionFactChecks.claimViolation(v20.context(), drawn, response.getReasoning());
        if (claim != null) {
            return claim;
        }
        String boundary = SecurityDecisionFactChecks.boundaryViolation(v20.context(), drawn, response.getAction());
        if (boundary != null) {
            return boundary;
        }
        return SecurityDecisionFactChecks.reasonViolation(SecurityDecisionFactChecks.reasonFindings(v20.context(),
                v20.settings(), drawn, response.getReasonCodes()));
    }

    /** The minimum action rule inputs: the decision facts the prompt stated, the resource and the host's settings. */
    public record MinimumActionCheck(DecisionFacts facts, String resourceClass, String actionFamily,
                                     MinimumActionRules.Settings settings) {
    }

    public Inspection inspect(String rawResponse, Prompt prompt, String requestId, String attempt) {
        return inspect(rawResponse, requestId, attempt, parsed -> findFactViolation(prompt, parsed));
    }

    private Inspection inspect(String rawResponse, String requestId, String attempt,
                               Function<SecurityDecisionResponseLite, String> factViolation) {
        PipelineExecutionContext inspectionContext = new PipelineExecutionContext(
                firstNonBlank(requestId, "security-decision") + "-raw-contract-" + attempt);
        SecurityDecisionResponseLite parsed = outputParser.parse(rawResponse, inspectionContext);
        boolean parsingFallback = Boolean.TRUE.equals(
                inspectionContext.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class));
        String parseFailureCategory = firstNonBlank(
                inspectionContext.getMetadata("securityDecisionParseFailureCategory", String.class),
                "NONE");
        String semanticViolation = factViolation.apply(parsed);
        String retryReason = parsingFallback ? "PARSER_" + parseFailureCategory : semanticViolation;
        return new Inspection(
                parsed,
                parsingFallback,
                parseFailureCategory,
                inspectionContext.getMetadata("securityDecisionRawOutputHash", String.class),
                inspectionContext.getMetadata("securityDecisionRawOutputLength", Integer.class),
                semanticViolation,
                retryReason);
    }

    private String findFactViolation(Prompt prompt, SecurityDecisionResponseLite response) {
        if (prompt == null || response == null) {
            return null;
        }
        String promptText = prompt.getContents() != null
                ? prompt.getContents().toLowerCase(Locale.ROOT)
                : "";
        // N-OUT-1 (G1-4): without a reason no reason claim is checked, but the action boundaries still are.
        String reasoning = response.getReasoning() != null ? response.getReasoning().toLowerCase(Locale.ROOT) : "";

        if (hasPromptFact(promptText, "mfaverified", "false")
                && claimsMfaVerified(reasoning)
                && !claimsMfaUnverified(reasoning)) {
            return "FALSE_MFA_VERIFIED_CLAIM";
        }
        if (hasPromptFact(promptText, "mfaverified", "true")
                && claimsMfaUnverified(reasoning)) {
            return "FALSE_MFA_UNVERIFIED_CLAIM";
        }
        boolean highSensitivity = hasPromptFact(promptText, "sensitivity", "high")
                || hasPromptFact(promptText, "sensitivity", "critical");
        if (highSensitivity && claimsLowSensitivity(reasoning)) {
            return "FALSE_LOW_SENSITIVITY_CLAIM";
        }
        boolean nonHighSensitivity = hasPromptFact(promptText, "sensitivity", "public")
                || hasPromptFact(promptText, "sensitivity", "low")
                || hasPromptFact(promptText, "sensitivity", "medium");
        if (nonHighSensitivity && claimsHighSensitivity(reasoning)) {
            return "FALSE_HIGH_SENSITIVITY_CLAIM";
        }
        if (hasPromptFact(promptText, "authorizationeffect", "allow")
                && claimsAuthorizationDenied(reasoning)) {
            return "FALSE_AUTHORIZATION_DENIED_CLAIM";
        }
        if (hasPromptFact(promptText, "ragrelevance", "no_documents")
                && hasPromptFact(promptText, "ragauthorizeddocumentcount", "0")
                && claimsAuthorizedSameResourceRag(reasoning)) {
            return "FALSE_AUTHORIZED_RAG_CLAIM";
        }
        String actionViolation = findActionBoundaryViolation(promptText, response.getAction());
        if (actionViolation != null) {
            return actionViolation;
        }
        return null;
    }

    private String findActionBoundaryViolation(String promptText, String rawAction) {
        String action = rawAction != null ? rawAction.trim().toUpperCase(Locale.ROOT) : "";
        String authorizationEffect = promptFactValue(promptText, "authorizationeffect");
        String tenantId = promptFactValue(promptText, "tenantid");
        String anomalyTrust = promptFactValue(promptText, "anomalysignaltrust");
        String anomalySignal = promptFactValue(promptText, "observedanomalysignal");
        boolean trustedConfirmedMalicious = anomalyTrust != null
                && anomalyTrust.startsWith("trusted_verification_input")
                && anomalySignal != null
                && (anomalySignal.contains("confirmed") || anomalySignal.contains("malicious"));
        boolean decisiveNegativeAuthorization = "deny".equals(authorizationEffect)
                || "block".equals(authorizationEffect);
        boolean tenantConflict = tenantId != null && tenantId.contains("conflicts_with_request_tenant");
        boolean scopeConflict = tenantConflict
                || hasConflictingPromptFacts(promptText, "tenantid")
                || hasConflictingPromptFacts(promptText, "organizationid");
        boolean requiredBlockEvidence = trustedConfirmedMalicious
                || decisiveNegativeAuthorization
                || scopeConflict
                || hasRequiredCanonicalAttack(promptText);
        boolean corroboratedCanonicalAttack = hasCorroboratedCanonicalAttack(promptText);
        boolean supportedBlockEvidence = requiredBlockEvidence || corroboratedCanonicalAttack;
        if ("BLOCK".equals(action) && !supportedBlockEvidence) {
            return "BLOCK_WITHOUT_DECISIVE_EVIDENCE";
        }
        if (requiredBlockEvidence && !"BLOCK".equals(action)) {
            return "REQUIRED_BLOCK_BOUNDARY_ACTION_MISMATCH";
        }

        boolean authorizationAllows = "allow".equals(authorizationEffect);

        boolean nonHighSensitivity = hasPromptFact(promptText, "sensitivity", "public")
                || hasPromptFact(promptText, "sensitivity", "low")
                || hasPromptFact(promptText, "sensitivity", "medium");
        boolean explicitAdverseEvidence = supportedBlockEvidence
                || hasAnyPromptFact(promptText, "approvalrequired", "true")
                || hasAnyPromptFact(promptText, "approvalmissing", "true")
                || hasAnyPromptFact(promptText, "blockeduser", "true")
                || statedFact(promptFactValue(promptText, "sessiondevicechange"))
                || statedFact(promptFactValue(promptText, "sessionnetworkchange"))
                || hasAnyPromptFact(promptText, "currentresourcefamilypresentindeniedrolescope", "true")
                || hasAnyPromptFact(promptText, "currentactionfamilypresentindeniedrolescope", "true")
                || hasAnyPromptFact(promptText, "currentresourcefamilypresentinexpectedrolescope", "false")
                || hasAnyPromptFact(promptText, "currentactionfamilypresentinexpectedrolescope", "false")
                || hasAnyPromptFact(promptText, "impossibletravel", "true")
                || positiveCount(promptFactValue(promptText, "threatcampaignmatchcount"))
                || positiveCount(promptFactValue(promptText, "recentdeniedaccesscount"))
                || positiveCount(promptFactValue(promptText, "recentblockcount"))
                || positiveCount(promptFactValue(promptText, "recentmfafailurecount"))
                || positiveCount(promptFactValue(promptText, "failedloginattempts"))
                || positiveCount(promptFactValue(promptText, "rolescopedeltacount"))
                || (anomalyTrust != null
                    && anomalyTrust.startsWith("trusted_verification_input")
                    && anomalySignal != null
                    && !anomalySignal.isBlank()
                    && !"none".equals(anomalySignal)
                    && !"unknown".equals(anomalySignal));
        if (authorizationAllows
                && nonHighSensitivity
                && !explicitAdverseEvidence
                && !"ALLOW".equals(action)) {
            return "REQUIRED_LOW_RISK_BOUNDARY_ACTION_MISMATCH";
        }
        return null;
    }

    private boolean hasCorroboratedCanonicalAttack(String promptText) {
        int categories = 0;
        boolean sessionOrRateAbuse = countAtLeast(promptFactValue(promptText, "failedloginattempts"), 100)
                && countAtLeast(promptFactValue(promptText, "recentrequestcount"), 100);
        if (sessionOrRateAbuse) {
            categories++;
        }
        if (hasPromptFact(promptText, "devicefingerprintmatch", "false")) {
            categories++;
        }
        boolean intentOrTransportTampering = hasPromptFact(promptText, "botuseragent", "true")
                || hasPromptFact(promptText, "tlsfingerprintaltered", "true")
                || hasPromptFact(promptText, "abnormalheaderorder", "true");
        if (intentOrTransportTampering) {
            categories++;
        }
        if (hasPromptFact(promptText, "impossibletravel", "true")) {
            categories++;
        }
        return categories >= 2;
    }

    private boolean hasRequiredCanonicalAttack(String promptText) {
        boolean sessionOrRateAbuse = countAtLeast(promptFactValue(promptText, "failedloginattempts"), 100)
                && countAtLeast(promptFactValue(promptText, "recentrequestcount"), 100);
        boolean deviceCompromise = hasPromptFact(promptText, "devicefingerprintmatch", "false");
        boolean intentOrTransportTampering = hasPromptFact(promptText, "botuseragent", "true")
                || hasPromptFact(promptText, "tlsfingerprintaltered", "true")
                || hasPromptFact(promptText, "abnormalheaderorder", "true");
        return sessionOrRateAbuse && deviceCompromise && intentOrTransportTampering;
    }

    private boolean hasPromptFact(String promptText, String key, String value) {
        return value.equals(promptFactValue(promptText, key));
    }

    private boolean hasAnyPromptFact(String promptText, String key, String value) {
        Matcher matcher = promptFactPattern(key).matcher(promptText);
        while (matcher.find()) {
            if (value.equals(matcher.group(1).trim().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private String promptFactValue(String promptText, String key) {
        Matcher matcher = promptFactPattern(key).matcher(promptText);
        String resolved = null;
        while (matcher.find()) {
            resolved = matcher.group(1).trim().toLowerCase(Locale.ROOT);
        }
        return resolved;
    }

    private Pattern promptFactPattern(String key) {
        return Pattern.compile(
                "(?m)^\\s*" + Pattern.quote(key) + "\\s*[:=]\\s*([^\\r\\n]+?)\\s*$",
                Pattern.CASE_INSENSITIVE);
    }

    private boolean hasConflictingPromptFacts(String promptText, String key) {
        Set<String> values = new LinkedHashSet<>();
        Matcher matcher = promptFactPattern(key).matcher(promptText);
        while (matcher.find()) {
            String value = matcher.group(1).trim().toLowerCase(Locale.ROOT);
            if (!value.isBlank() && !"unknown".equals(value) && !"not_applicable".equals(value)) {
                values.add(value);
            }
        }
        return values.size() > 1;
    }

    private boolean positiveCount(String value) {
        return countAtLeast(value, 1);
    }

    /** Whether the prompt states the fact: a value that is neither blank, unknown, none nor not applicable (W2-14). */
    private boolean statedFact(String value) {
        return value != null && !value.isBlank() && !"unknown".equals(value) && !"none".equals(value)
                && !"not_applicable".equals(value);
    }

    private boolean countAtLeast(String value, int minimum) {
        if (value == null) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank() || "unknown".equals(normalized)
                || "none".equals(normalized) || "not_applicable".equals(normalized)) {
            return false;
        }
        try {
            Matcher matcher = Pattern.compile("^\\d+").matcher(normalized);
            return matcher.find() && Integer.parseInt(matcher.group()) >= minimum;
        }
        catch (NumberFormatException ignored) {
            return false;
        }
    }

    private boolean claimsAuthorizedSameResourceRag(String reasoning) {
        String normalized = reasoning.replaceAll("\\s+", " ").trim();
        return normalized.equals("authorization allows access, and authorized rag is relevant to the same resource.")
                || normalized.equals("authorization allows access, the personal baseline is established, "
                        + "and authorized rag is relevant to the same resource.");
    }

    private String firstNonBlank(String value, String fallback) {
        return value != null && !value.isBlank() ? value : fallback;
    }

    public record Inspection(
            SecurityDecisionResponseLite response,
            boolean parsingFallback,
            String parseFailureCategory,
            String rawOutputHash,
            Integer rawOutputLength,
            String semanticViolation,
            String retryReason) {

        public boolean requiresRetry() {
            return parsingFallback || semanticViolation != null;
        }
    }
}
