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

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.ai.chat.prompt.Prompt;

/**
 * Inspects a raw security-decision response without mutating the live pipeline context.
 */
public final class SecurityDecisionRawOutputContractInspector {

    private final SecurityDecisionOutputParser outputParser = new SecurityDecisionOutputParser();

    public Inspection inspect(String rawResponse, Prompt prompt, String requestId, String attempt) {
        PipelineExecutionContext inspectionContext = new PipelineExecutionContext(
                firstNonBlank(requestId, "security-decision") + "-raw-contract-" + attempt);
        SecurityDecisionResponseLite parsed = outputParser.parse(rawResponse, inspectionContext);
        boolean parsingFallback = Boolean.TRUE.equals(
                inspectionContext.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class));
        String parseFailureCategory = firstNonBlank(
                inspectionContext.getMetadata("securityDecisionParseFailureCategory", String.class),
                "NONE");
        String semanticViolation = findFactViolation(prompt, parsed);
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
        if (prompt == null || response == null || response.getReasoning() == null) {
            return null;
        }
        String promptText = prompt.getContents() != null
                ? prompt.getContents().toLowerCase(Locale.ROOT)
                : "";
        String reasoning = response.getReasoning().toLowerCase(Locale.ROOT);

        if (hasPromptFact(promptText, "verificationrequired", "false")
                && claimsFreshVerificationRequired(reasoning)) {
            return "FALSE_VERIFICATION_REQUIRED_CLAIM";
        }
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
        boolean verificationRequired = hasPromptFact(promptText, "verificationrequired", "true");
        boolean mfaUnverified = hasPromptFact(promptText, "mfaverified", "false");
        if (authorizationAllows && verificationRequired && mfaUnverified && !supportedBlockEvidence
                && !"CHALLENGE".equals(action)) {
            return "REQUIRED_VERIFICATION_BOUNDARY_ACTION_MISMATCH";
        }

        boolean nonHighSensitivity = hasPromptFact(promptText, "sensitivity", "public")
                || hasPromptFact(promptText, "sensitivity", "low")
                || hasPromptFact(promptText, "sensitivity", "medium");
        boolean explicitAdverseEvidence = supportedBlockEvidence
                || hasAnyPromptFact(promptText, "approvalrequired", "true")
                || hasAnyPromptFact(promptText, "approvalmissing", "true")
                || hasAnyPromptFact(promptText, "blockeduser", "true")
                || hasAnyPromptFact(promptText, "contextbindinghashmismatch", "true")
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
                || (anomalySignal != null
                    && !anomalySignal.isBlank()
                    && !"none".equals(anomalySignal)
                    && !"unknown".equals(anomalySignal));
        if (authorizationAllows
                && !verificationRequired
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

    private boolean claimsFreshVerificationRequired(String reasoning) {
        if (reasoning.contains("verification is not required")
                || reasoning.contains("verification not required")
                || reasoning.contains("no fresh verification")) {
            return false;
        }
        return reasoning.contains("fresh verification is required")
                || reasoning.contains("fresh verification required")
                || reasoning.contains("requires fresh verification")
                || reasoning.contains("verification is required before");
    }

    private boolean claimsMfaVerified(String reasoning) {
        return reasoning.contains("mfa is verified")
                || reasoning.contains("mfa verified")
                || reasoning.contains("mfaverified=true")
                || reasoning.contains("mfaverified = true");
    }

    private boolean claimsMfaUnverified(String reasoning) {
        return reasoning.contains("mfa is not verified")
                || reasoning.contains("mfa not verified")
                || reasoning.contains("mfa unverified")
                || reasoning.contains("mfaverified=false")
                || reasoning.contains("mfaverified = false");
    }

    private boolean claimsLowSensitivity(String reasoning) {
        return reasoning.contains("low sensitivity")
                || reasoning.contains("low-resource sensitivity")
                || reasoning.contains("non-high sensitivity");
    }

    private boolean claimsHighSensitivity(String reasoning) {
        if (reasoning.contains("not high sensitivity")
                || reasoning.contains("non-high sensitivity")) {
            return false;
        }
        return reasoning.contains("high sensitivity")
                || reasoning.contains("high-sensitivity")
                || reasoning.contains("critical sensitivity");
    }

    private boolean claimsAuthorizationDenied(String reasoning) {
        return reasoning.contains("authorization denied")
                || reasoning.contains("authorization is denied")
                || reasoning.contains("authorizationeffect=deny")
                || reasoning.contains("authorizationeffect = deny");
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