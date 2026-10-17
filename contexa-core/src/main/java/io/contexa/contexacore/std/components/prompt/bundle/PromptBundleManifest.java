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
package io.contexa.contexacore.std.components.prompt.bundle;

import java.util.List;
import java.util.Objects;

/**
 * The manifest of one prompt bundle (version management design 6.1). The bundle hash is the identity: it is the
 * SHA-256 of the eleven element hashes in a fixed order. The other fields describe the bundle and do not enter the hash.
 * N-GOV-2: {@code evaluationScenarioFamilies} names the scenario families an evaluation of this bundle must cover; a
 * manifest that names none needs the default families of the empirical evaluation.
 */
public record PromptBundleManifest(
        String promptKey,
        String bundleVersion,
        String bundleHash,
        List<PromptBundleElement> elements,
        PromptBundleGoldenInputs goldenInputs,
        String parentVersion,
        String changeSummary,
        List<String> problemIds,
        String author,
        String frozenOn,
        String vocabularyVersion,
        List<String> compatibleVocabularyVersions,
        List<String> rollbackTargets,
        List<String> declaredModelProfiles,
        List<String> evaluationScenarioFamilies) {

    public PromptBundleManifest {
        promptKey = requireText(promptKey, "promptKey");
        bundleVersion = requireText(bundleVersion, "bundleVersion");
        elements = List.copyOf(Objects.requireNonNull(elements, "elements"));
        problemIds = problemIds == null ? List.of() : List.copyOf(problemIds);
        compatibleVocabularyVersions = compatibleVocabularyVersions == null
                ? List.of() : List.copyOf(compatibleVocabularyVersions);
        rollbackTargets = rollbackTargets == null ? List.of() : List.copyOf(rollbackTargets);
        declaredModelProfiles = declaredModelProfiles == null ? List.of() : List.copyOf(declaredModelProfiles);
        evaluationScenarioFamilies = evaluationScenarioFamilies == null
                ? List.of() : List.copyOf(evaluationScenarioFamilies);
        String expected = PromptBundleHashes.bundleHash(elements);
        if (!expected.equals(bundleHash)) {
            throw new IllegalArgumentException("Prompt bundle " + promptKey + "@" + bundleVersion
                    + " declares hash " + bundleHash + " but its elements hash to " + expected);
        }
    }

    /** A manifest that declares no evaluation scenario families (N-GOV-2), as the bundle tests compute it. */
    public PromptBundleManifest(String promptKey, String bundleVersion, String bundleHash,
                                List<PromptBundleElement> elements, PromptBundleGoldenInputs goldenInputs,
                                String parentVersion, String changeSummary, List<String> problemIds, String author,
                                String frozenOn, String vocabularyVersion, List<String> compatibleVocabularyVersions,
                                List<String> rollbackTargets, List<String> declaredModelProfiles) {
        this(promptKey, bundleVersion, bundleHash, elements, goldenInputs, parentVersion, changeSummary, problemIds,
                author, frozenOn, vocabularyVersion, compatibleVocabularyVersions, rollbackTargets, declaredModelProfiles,
                List.of());
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }
}
