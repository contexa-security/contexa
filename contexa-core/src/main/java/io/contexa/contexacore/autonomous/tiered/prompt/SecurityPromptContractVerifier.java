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
import io.contexa.contexacore.autonomous.context.snapshot.CurrentRequestSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SecurityPromptContractVerifier {

    private static final Pattern NARRATIVE_TIME_PATTERN = Pattern.compile(" at (?<hour>\\d{2}):(?<minute>\\d{2})\\.");
    private static final Pattern COMPACTED_LINE_PATTERN = Pattern.compile("\\+\\s+(?<count>\\d+)\\s+additional lines compacted\\.");
    private static final Set<String> SEMANTIC_AUTH_TYPES = Set.of("PASSWORD", "PASSKEY", "SSO", "TOKEN", "SESSION", "MFA_ONLY", "UNKNOWN");
    private static final Set<String> SEMANTIC_ACTION_FAMILIES = Set.of("READ", "WRITE", "DELETE", "EXPORT", "ADMIN", "EXECUTE", "UNKNOWN");
    private static final Set<String> SEMANTIC_RESOURCE_FAMILIES = Set.of("PUBLIC", "NORMAL", "SENSITIVE", "CRITICAL", "UNKNOWN");
    private static final List<String> SYSTEM_COMPARISON_LABELS = List.of(
            "CurrentAccessHour",
            "CurrentAccessHourPresentInObservedHours",
            "CurrentDayPresentInObservedDays",
            "CurrentPathPresentInObservedPaths",
            "CurrentBrowserPresentInObservedBrowsers",
            "CurrentNetworkPresentInObservedNetworks",
            "CurrentOperatingSystemPresentInObservedOperatingSystems",
            "CurrentAuthenticationTypePresentInObservedAuthTypes",
            "CurrentActionFamilyPresentInObservedActions",
            "CurrentResourceFamilyPresentInObservedResources",
            "CurrentActionFamilyPresentInExpectedRoleScope",
            "CurrentResourceFamilyPresentInExpectedRoleScope");

    private SecurityPromptContractVerifier() {
    }

    public static SecurityPromptContractAudit audit(
            String systemPrompt,
            String userPrompt,
            SecurityPromptBuildContext buildContext) {
        LearningContextEvidence learningEvidence = buildContext != null ? buildContext.getLearningContextEvidence() : null;
        CurrentLearningContextSnapshot current = learningEvidence != null ? learningEvidence.current() : null;
        CanonicalSecurityContext canonicalSecurityContext = buildContext != null ? buildContext.getCanonicalSecurityContext() : null;

        CurrentRequestSnapshot renderedRequestSnapshot = new CurrentRequestSnapshot(
                extractNarrativeTime(userPrompt),
                extractLineValue(userPrompt, "CurrentAccessHour"),
                extractLineValue(userPrompt, "CurrentDayOfWeek"),
                extractLineValue(userPrompt, "AuthenticationType"),
                extractLineValue(userPrompt, "RequestPath"),
                extractLineValue(userPrompt, "CurrentPathFamily"),
                firstNonBlank(extractLineValue(userPrompt, "CurrentActionFamily"), extractLineValue(userPrompt, "ActionFamily")),
                firstNonBlank(extractLineValue(userPrompt, "CurrentResourceFamily"), extractLineValue(userPrompt, "ResourceType")),
                extractLineValue(userPrompt, "DeviceBrowser"),
                extractLineValue(userPrompt, "DeviceOs"),
                firstNonBlank(extractLineValue(userPrompt, "CurrentNetwork"), extractLineValue(userPrompt, "IpBand")));

        Map<String, Object> renderedLearningSnapshot = new LinkedHashMap<>();
        renderedLearningSnapshot.put("personalBaselineEstablished",
                learningEvidence != null && learningEvidence.personalBaseline() != null && learningEvidence.personalBaseline().established());
        renderedLearningSnapshot.put("supportingBaselineAvailable",
                learningEvidence != null && learningEvidence.supportingBaseline() != null && learningEvidence.supportingBaseline().available());
        renderedLearningSnapshot.put("personalRetrievedDocCount",
                learningEvidence == null ? 0 : learningEvidence.personalRetrievedEvidence().size());
        renderedLearningSnapshot.put("supportingRetrievedDocCount",
                learningEvidence == null ? 0 : learningEvidence.supportingRetrievedEvidence().size());
        renderedLearningSnapshot.put("historicalComparableScope",
                learningEvidence != null ? learningEvidence.historicalComparableScope() : null);
        renderedLearningSnapshot.put("observedPatternEvidenceScope",
                learningEvidence != null ? learningEvidence.observedPatternEvidenceScope() : null);
        renderedLearningSnapshot.put("carryRequiredFacts",
                learningEvidence == null ? List.of() : learningEvidence.carryRequiredFacts());
        renderedLearningSnapshot.put("carryMissingFacts",
                learningEvidence == null ? List.of() : learningEvidence.carryMissingFacts());
        renderedLearningSnapshot.put("strongestLearningDelta",
                learningEvidence != null && learningEvidence.strongestDelta() != null
                        ? learningEvidence.strongestDelta().description()
                        : null);
        renderedLearningSnapshot.put("currentRequestCombinationSeenCount",
                learningEvidence == null || learningEvidence.personalRetrievedEvidence().isEmpty()
                        ? "UNKNOWN"
                        : learningEvidence.currentRequestCombinationSeenCount());
        renderedLearningSnapshot.put("currentRequestCombinationEvidenceScope",
                learningEvidence != null ? learningEvidence.currentRequestCombinationEvidenceScope() : null);
        renderedLearningSnapshot.put("currentRequestCombinationComparedDimensions",
                learningEvidence != null ? learningEvidence.currentRequestCombinationComparedDimensions() : null);
        renderedLearningSnapshot.put("currentRequestClosestObservedOverlap",
                learningEvidence != null ? learningEvidence.currentRequestClosestObservedOverlap() : null);
        renderedLearningSnapshot.put("strongestCurrentRequestCombinationDelta",
                learningEvidence != null ? learningEvidence.strongestCurrentRequestCombinationDelta() : null);
        renderedLearningSnapshot.put("currentRequestCombinationSummary",
                learningEvidence != null ? learningEvidence.currentRequestCombinationSummary() : null);
        renderedLearningSnapshot.put("observedComparableCombination1",
                learningEvidence != null ? learningEvidence.representativeCombinationSummary() : null);

        Map<String, Object> renderedLabelMatrix = new LinkedHashMap<>();
        for (String label : SYSTEM_COMPARISON_LABELS) {
            renderedLabelMatrix.put(label, extractLineValue(userPrompt, label));
        }
        if (learningEvidence != null) {
            for (String fact : learningEvidence.carryRequiredFacts()) {
                renderedLabelMatrix.putIfAbsent(fact, extractLineValue(userPrompt, fact));
            }
        }

        List<String> violations = new ArrayList<>();
        validateSystemPromptIntegrity(systemPrompt, violations);
        validateNarrativeTimeConsistency(userPrompt, violations);
        validateResolvedAuthorizationEffectNotMissing(userPrompt, violations);
        validateSemanticAuthenticationVocabulary(userPrompt, current, violations);
        validateSemanticRequestAndObservedVocabulary(userPrompt, violations);
        validateRequiredLabels(systemPrompt, userPrompt, learningEvidence, canonicalSecurityContext, violations);
        validatePersonalSupportingHierarchy(userPrompt, learningEvidence, violations);
        validateWorkProfileAnchorPresence(userPrompt, learningEvidence, violations);
        validateRoleScopeUncertainty(userPrompt, violations);
        validateComparableSummaryProvenance(userPrompt, learningEvidence, violations);
        validateObservedPatternScope(userPrompt, learningEvidence, violations);
        validateCombinationEvidenceScope(userPrompt, learningEvidence, violations);
        validatePathComparisonResolution(userPrompt, learningEvidence, violations);
        validateCarryCompleteness(learningEvidence, violations);

        return new SecurityPromptContractAudit(
                immutableNullableMap(renderedRequestSnapshot.toMap()),
                immutableNullableMap(renderedLearningSnapshot),
                immutableNullableMap(renderedLabelMatrix),
                immutableNullableMap(countCompactedLinesBySection(userPrompt)),
                List.copyOf(new LinkedHashSet<>(violations)));
    }

    private static void validateNarrativeTimeConsistency(String userPrompt, List<String> violations) {
        String narrativeTime = extractNarrativeTime(userPrompt);
        String currentAccessHour = extractLineValue(userPrompt, "CurrentAccessHour");
        if (!StringUtils.hasText(narrativeTime) || !StringUtils.hasText(currentAccessHour)) {
            return;
        }
        if (!currentAccessHour.trim().matches("\\d{1,2}")) {
            return;
        }
        Matcher matcher = NARRATIVE_TIME_PATTERN.matcher(" at " + narrativeTime + ".");
        if (matcher.find()) {
            String narrativeHour = matcher.group("hour");
            if (!narrativeHour.equals(String.format("%02d", safeParseInt(currentAccessHour)))) {
                violations.add("REQUEST_TIME_MISMATCH");
            }
        }
    }

    private static void validateSystemPromptIntegrity(String systemPrompt, List<String> violations) {
        if (!StringUtils.hasText(systemPrompt)) {
            return;
        }
        for (String line : systemPrompt.split("\\R")) {
            String normalized = line != null ? line.trim() : "";
            if (normalized.endsWith("...")) {
                violations.add("SYSTEM_PROMPT_LINE_TRUNCATED");
                return;
            }
        }
    }

    private static void validateResolvedAuthorizationEffectNotMissing(String userPrompt, List<String> violations) {
        String authorizationEffect = extractLineValue(userPrompt, "AuthorizationEffect");
        if (StringUtils.hasText(authorizationEffect)
                && userPrompt != null
                && userPrompt.contains("Bridge missing context: AUTHORIZATION_EFFECT.")) {
            violations.add("AUTHORIZATION_EFFECT_RESOLVED_BUT_STILL_MISSING");
        }
    }

    private static void validateSemanticAuthenticationVocabulary(
            String userPrompt,
            CurrentLearningContextSnapshot current,
            List<String> violations) {
        String renderedAuthenticationType = extractLineValue(userPrompt, "AuthenticationType");
        String currentAuthenticationType = current != null ? current.authenticationType() : null;
        if (StringUtils.hasText(renderedAuthenticationType)
                && !SEMANTIC_AUTH_TYPES.contains(renderedAuthenticationType.trim().toUpperCase())) {
            violations.add("REQUEST_AUTH_VOCABULARY_NOT_SEMANTIC");
        }
        if (StringUtils.hasText(currentAuthenticationType)
                && !SEMANTIC_AUTH_TYPES.contains(currentAuthenticationType.trim().toUpperCase())) {
            violations.add("LEARNING_AUTH_VOCABULARY_NOT_SEMANTIC");
        }
    }

    private static void validateSemanticRequestAndObservedVocabulary(String userPrompt, List<String> violations) {
        validateSemanticToken(
                firstNonBlank(extractLineValue(userPrompt, "CurrentActionFamily"), extractLineValue(userPrompt, "ActionFamily")),
                SEMANTIC_ACTION_FAMILIES,
                "REQUEST_ACTION_VOCABULARY_NOT_SEMANTIC",
                violations);
        validateSemanticToken(
                firstNonBlank(extractLineValue(userPrompt, "CurrentResourceFamily"), extractLineValue(userPrompt, "ResourceType")),
                SEMANTIC_RESOURCE_FAMILIES,
                "REQUEST_RESOURCE_VOCABULARY_NOT_SEMANTIC",
                violations);
        validateSemanticList(extractLineValue(userPrompt, "ObservedAuthenticationTypes"), SEMANTIC_AUTH_TYPES, "OBSERVED_AUTH_VOCABULARY_NOT_SEMANTIC", violations);
        validateSemanticList(extractLineValue(userPrompt, "ObservedActionFamilies"), SEMANTIC_ACTION_FAMILIES, "OBSERVED_ACTION_VOCABULARY_NOT_SEMANTIC", violations);
        validateSemanticList(extractLineValue(userPrompt, "ObservedResourceFamilies"), SEMANTIC_RESOURCE_FAMILIES, "OBSERVED_RESOURCE_VOCABULARY_NOT_SEMANTIC", violations);
    }

    private static void validateRequiredLabels(
            String systemPrompt,
            String userPrompt,
            LearningContextEvidence learningEvidence,
            CanonicalSecurityContext canonicalSecurityContext,
            List<String> violations) {
        for (String label : SYSTEM_COMPARISON_LABELS) {
            if (systemPrompt != null
                    && systemPrompt.contains(label)
                    && isLabelExpected(label, learningEvidence, canonicalSecurityContext)
                    && extractLineValue(userPrompt, label) == null) {
                violations.add("MISSING_REQUIRED_LABEL:" + label);
            }
        }
        if (learningEvidence != null) {
            for (String fact : learningEvidence.carryRequiredFacts()) {
                if (extractLineValue(userPrompt, fact) == null) {
                    violations.add("LEARNING_CARRY_MISSING:" + fact);
                }
            }
        }
        CanonicalSecurityContext.RoleScopeProfile roleScopeProfile =
                canonicalSecurityContext != null ? canonicalSecurityContext.getRoleScopeProfile() : null;
        if (roleScopeProfile != null && StringUtils.hasText(roleScopeProfile.getCurrentActionFamily())
                && extractLineValue(userPrompt, "CurrentActionFamilyPresentInExpectedRoleScope") == null) {
            violations.add("MISSING_REQUIRED_LABEL:CurrentActionFamilyPresentInExpectedRoleScope");
        }
        if (roleScopeProfile != null && StringUtils.hasText(roleScopeProfile.getCurrentResourceFamily())
                && extractLineValue(userPrompt, "CurrentResourceFamilyPresentInExpectedRoleScope") == null) {
            violations.add("MISSING_REQUIRED_LABEL:CurrentResourceFamilyPresentInExpectedRoleScope");
        }
    }

    private static void validatePersonalSupportingHierarchy(
            String userPrompt,
            LearningContextEvidence learningEvidence,
            List<String> violations) {
        BaselineEvidenceSnapshot personalBaseline = learningEvidence != null ? learningEvidence.personalBaseline() : null;
        if (personalBaseline != null
                && personalBaseline.established()
                && userPrompt != null
                && userPrompt.contains("supporting baseline history as limited comparison evidence only")) {
            violations.add("PERSONAL_BASELINE_ESTABLISHED_BUT_SUPPORTING_ONLY_WARNING_PRESENT");
        }
    }

    private static void validateWorkProfileAnchorPresence(
            String userPrompt,
            LearningContextEvidence learningEvidence,
            List<String> violations) {
        if (!StringUtils.hasText(extractLineValue(userPrompt, "BaselineProfileStatus"))) {
            return;
        }
        if (extractLineValue(userPrompt, "WorkProfileEvidenceState") == null) {
            violations.add("WORK_PROFILE_EVIDENCE_STATE_MISSING");
        }
        if (extractLineValue(userPrompt, "ObservedPatternEvidenceScope") == null) {
            violations.add("OBSERVED_PATTERN_EVIDENCE_SCOPE_MISSING");
        }
        if (learningEvidence != null
                && !learningEvidence.personalRetrievedEvidence().isEmpty()
                && extractLineValue(userPrompt, "HistoricalComparableScope") == null) {
            violations.add("HISTORICAL_COMPARABLE_SCOPE_MISSING");
        }
        if (extractLineValue(userPrompt, "ApprovalStatus") == null) {
            violations.add("APPROVAL_STATUS_MISSING");
        }
        if (extractLineValue(userPrompt, "ObjectiveAlignmentEvidence") == null) {
            violations.add("OBJECTIVE_ALIGNMENT_EVIDENCE_MISSING");
        }
        if (extractLineValue(userPrompt, "RecentPermissionChanges") == null) {
            violations.add("RECENT_PERMISSION_CHANGES_MISSING");
        }
    }

    private static void validateRoleScopeUncertainty(String userPrompt, List<String> violations) {
        String evidenceState = extractLineValue(userPrompt, "RoleScopeEvidenceState");
        String deltaCount = extractLineValue(userPrompt, "RoleScopeDeltaCount");
        String strongestDelta = extractLineValue(userPrompt, "StrongestRoleScopeDelta");
        if (!StringUtils.hasText(evidenceState)) {
            return;
        }
        String normalized = evidenceState.trim().toUpperCase();
        boolean unreliable = normalized.contains("PROVISIONAL")
                || normalized.contains("PARTIAL")
                || normalized.contains("INCOMPLETE")
                || normalized.contains("THIN")
                || normalized.contains("FALLBACK");
        if (unreliable && ("0".equals(deltaCount) || "none".equalsIgnoreCase(strongestDelta))) {
            violations.add("ROLE_SCOPE_PROVISIONAL_ZERO_DELTA_CONFLICT");
        }
    }

    private static void validateComparableSummaryProvenance(
            String userPrompt,
            LearningContextEvidence learningEvidence,
            List<String> violations) {
        if (learningEvidence == null || learningEvidence.personalRetrievedEvidence().isEmpty()) {
            return;
        }
        String comparableScope = extractLineValue(userPrompt, "HistoricalComparableScope");
        String comparableCount = extractLineValue(userPrompt, "HistoricalComparableCount");
        String comparableSummary = extractLineValue(userPrompt, "HistoricalComparableSummary");
        if (!"PERSONAL_RETRIEVED_SUBSET".equalsIgnoreCase(comparableScope)) {
            violations.add("HISTORICAL_COMPARABLE_SCOPE_INCORRECT");
        }
        if (StringUtils.hasText(comparableCount)
                && !"0".equals(comparableCount.trim())
                && StringUtils.hasText(comparableSummary)
                && !comparableSummary.contains("Source=PERSONAL_RETRIEVED_SUBSET")) {
            violations.add("HISTORICAL_COMPARABLE_SUMMARY_PROVENANCE_MISSING");
        }
        if (StringUtils.hasText(comparableSummary) && comparableSummary.endsWith("...")) {
            violations.add("HISTORICAL_COMPARABLE_SUMMARY_TRUNCATED");
        }
        String comparableExample = extractLineValue(userPrompt, "ComparableExample1");
        if (StringUtils.hasText(comparableExample) && comparableExample.endsWith("...")) {
            violations.add("COMPARABLE_EXAMPLE_TRUNCATED");
        }
    }

    private static void validateObservedPatternScope(
            String userPrompt,
            LearningContextEvidence learningEvidence,
            List<String> violations) {
        if (learningEvidence == null) {
            return;
        }
        String renderedScope = extractLineValue(userPrompt, "ObservedPatternEvidenceScope");
        String expectedScope = learningEvidence.observedPatternEvidenceScope();
        if (!StringUtils.hasText(renderedScope)) {
            return;
        }
        if (StringUtils.hasText(expectedScope) && !expectedScope.equalsIgnoreCase(renderedScope)) {
            violations.add("OBSERVED_PATTERN_EVIDENCE_SCOPE_INCORRECT");
        }
    }

    private static void validateCombinationEvidenceScope(
            String userPrompt,
            LearningContextEvidence learningEvidence,
            List<String> violations) {
        if (!StringUtils.hasText(extractLineValue(userPrompt, "CurrentRequestCombinationSeenCount"))
                && !StringUtils.hasText(extractLineValue(userPrompt, "CurrentRequestClosestObservedOverlap"))) {
            return;
        }
        String scope = extractLineValue(userPrompt, "CurrentRequestCombinationEvidenceScope");
        if (!StringUtils.hasText(scope)) {
            violations.add("CURRENT_REQUEST_COMBINATION_SCOPE_MISSING");
            return;
        }
        if (learningEvidence != null
                && !learningEvidence.personalRetrievedEvidence().isEmpty()
                && !"PERSONAL_RETRIEVED_SUBSET".equalsIgnoreCase(scope)) {
            violations.add("CURRENT_REQUEST_COMBINATION_SCOPE_INCORRECT");
        }
    }

    private static void validatePathComparisonResolution(
            String userPrompt,
            LearningContextEvidence learningEvidence,
            List<String> violations) {
        if (learningEvidence == null
                || learningEvidence.personalRetrievedEvidence().isEmpty()
                || learningEvidence.current() == null
                || !StringUtils.hasText(learningEvidence.current().pathFamily())) {
            return;
        }
        String renderedPathPresence = extractLineValue(userPrompt, "CurrentPathPresentInObservedPaths");
        if ("UNKNOWN".equalsIgnoreCase(renderedPathPresence)) {
            violations.add("PATH_COMPARISON_UNRESOLVED_WITH_PERSONAL_EVIDENCE");
        }
    }

    private static void validateCarryCompleteness(LearningContextEvidence learningEvidence, List<String> violations) {
        if (learningEvidence != null && !learningEvidence.carryMissingFacts().isEmpty()) {
            violations.add("LEARNING_CARRY_INCOMPLETE");
        }
    }

    private static boolean isLabelExpected(
            String label,
            LearningContextEvidence learningEvidence,
            CanonicalSecurityContext canonicalSecurityContext) {
        CurrentLearningContextSnapshot current = learningEvidence != null ? learningEvidence.current() : null;
        return switch (label) {
            case "CurrentAccessHour", "CurrentAccessHourPresentInObservedHours" ->
                    current != null && StringUtils.hasText(current.accessHour());
            case "CurrentDayPresentInObservedDays" ->
                    current != null && StringUtils.hasText(current.dayOfWeek());
            case "CurrentPathPresentInObservedPaths" ->
                    current != null && StringUtils.hasText(current.pathFamily());
            case "CurrentBrowserPresentInObservedBrowsers" ->
                    current != null && StringUtils.hasText(current.browser());
            case "CurrentNetworkPresentInObservedNetworks" ->
                    current != null && StringUtils.hasText(current.network());
            case "CurrentOperatingSystemPresentInObservedOperatingSystems" ->
                    current != null && StringUtils.hasText(current.operatingSystem());
            case "CurrentAuthenticationTypePresentInObservedAuthTypes" ->
                    current != null && StringUtils.hasText(current.authenticationType());
            case "CurrentActionFamilyPresentInObservedActions" ->
                    current != null && StringUtils.hasText(current.actionFamily());
            case "CurrentResourceFamilyPresentInObservedResources" ->
                    current != null && StringUtils.hasText(current.resourceFamily());
            case "CurrentActionFamilyPresentInExpectedRoleScope" ->
                    canonicalSecurityContext != null
                            && canonicalSecurityContext.getRoleScopeProfile() != null
                            && StringUtils.hasText(canonicalSecurityContext.getRoleScopeProfile().getCurrentActionFamily());
            case "CurrentResourceFamilyPresentInExpectedRoleScope" ->
                    canonicalSecurityContext != null
                            && canonicalSecurityContext.getRoleScopeProfile() != null
                            && StringUtils.hasText(canonicalSecurityContext.getRoleScopeProfile().getCurrentResourceFamily());
            default -> true;
        };
    }

    private static String extractNarrativeTime(String userPrompt) {
        if (!StringUtils.hasText(userPrompt)) {
            return null;
        }
        Matcher matcher = NARRATIVE_TIME_PATTERN.matcher(userPrompt);
        if (!matcher.find()) {
            return null;
        }
        return matcher.group("hour") + ":" + matcher.group("minute");
    }

    private static String extractLineValue(String prompt, String label) {
        if (!StringUtils.hasText(prompt) || !StringUtils.hasText(label)) {
            return null;
        }
        String prefix = label + ":";
        for (String line : prompt.split("\\R")) {
            String trimmed = line.stripLeading();
            if (trimmed.startsWith(prefix)) {
                return trimmed.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    private static Map<String, Integer> countCompactedLinesBySection(String userPrompt) {
        if (!StringUtils.hasText(userPrompt)) {
            return Map.of();
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        String currentSection = "GLOBAL";
        for (String line : userPrompt.split("\\R")) {
            String trimmed = line.stripLeading();
            if (trimmed.startsWith("===") && trimmed.endsWith("===")) {
                currentSection = trimmed;
                continue;
            }
            Matcher matcher = COMPACTED_LINE_PATTERN.matcher(trimmed);
            if (matcher.find()) {
                counts.merge(currentSection, Integer.parseInt(matcher.group("count")), Integer::sum);
            }
        }
        return Map.copyOf(counts);
    }

    private static int safeParseInt(String value) {
        try {
            return Integer.parseInt(value.trim());
        }
        catch (Exception ignored) {
            return 0;
        }
    }

    private static void validateSemanticToken(
            String value,
            Set<String> allowedValues,
            String violationCode,
            List<String> violations) {
        if (!StringUtils.hasText(value) || allowedValues == null || violationCode == null) {
            return;
        }
        String normalized = value.trim().toUpperCase();
        if (!allowedValues.contains(normalized)) {
            violations.add(violationCode);
        }
    }

    private static void validateSemanticList(
            String value,
            Set<String> allowedValues,
            String violationCode,
            List<String> violations) {
        if (!StringUtils.hasText(value) || allowedValues == null || violationCode == null) {
            return;
        }
        for (String token : value.split("[,|]")) {
            String normalized = token == null ? null : token.trim().toUpperCase();
            if (!StringUtils.hasText(normalized) || "UNKNOWN".equals(normalized)) {
                continue;
            }
            if (!allowedValues.contains(normalized)) {
                violations.add(violationCode);
                return;
            }
        }
    }

    private static String firstNonBlank(String... values) {
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

    private static <K, V> Map<K, V> immutableNullableMap(Map<K, V> input) {
        if (input == null || input.isEmpty()) {
            return Map.of();
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(input));
    }
}
