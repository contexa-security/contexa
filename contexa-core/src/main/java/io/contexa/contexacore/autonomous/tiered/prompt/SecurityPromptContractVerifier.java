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
import io.contexa.contexacore.autonomous.learning.evidence.CurrentLearningContextSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;

public final class SecurityPromptContractVerifier {

    private SecurityPromptContractVerifier() {
    }

    /**
     * W4-8 (S-28, plan 9, plan 2.3 A11): the audit of a render. The prompt inspector holds a render to its dictionary;
     * the render is audited for its system text, and its snapshots are the structured sources it was drawn from: the
     * current request of the learning evidence and the learning state. The decision facts compare, so it has no label
     * matrix and no compacted lines (plan 6-2: the label checks of the v19 section prompt went with it).
     */
    public static SecurityPromptContractAudit audit(String systemPrompt, SecurityPromptBuildContext buildContext) {
        LearningContextEvidence learningEvidence = buildContext != null ? buildContext.getLearningContextEvidence() : null;
        CurrentLearningContextSnapshot current = learningEvidence != null ? learningEvidence.current() : null;
        CanonicalSecurityContext canonical = buildContext != null ? buildContext.getCanonicalSecurityContext() : null;
        CanonicalSecurityContext.Resource resource = canonical != null ? canonical.getResource() : null;
        CurrentRequestSnapshot request = new CurrentRequestSnapshot(
                null,
                current != null ? current.accessHour() : null,
                current != null ? current.dayOfWeek() : null,
                current != null ? current.authenticationType() : null,
                resource != null ? resource.getRequestPath() : null,
                current != null ? current.pathFamily() : null,
                current != null ? current.actionFamily() : null,
                current != null ? current.resourceFamily() : null,
                current != null ? current.browser() : null,
                current != null ? current.operatingSystem() : null,
                current != null ? current.network() : null);
        List<String> violations = new ArrayList<>();
        validateSystemPromptIntegrity(systemPrompt, violations);
        return new SecurityPromptContractAudit(
                immutableNullableMap(request.toMap()),
                immutableNullableMap(learningSnapshot(learningEvidence)),
                Map.of(),
                Map.of(),
                List.copyOf(violations));
    }

    /** The learning state the render was drawn from (structured, shared by the v19 and the v20 audit). */
    private static Map<String, Object> learningSnapshot(LearningContextEvidence learningEvidence) {
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
        return renderedLearningSnapshot;
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


    private static <K, V> Map<K, V> immutableNullableMap(Map<K, V> input) {
        if (input == null || input.isEmpty()) {
            return Map.of();
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(input));
    }
}
