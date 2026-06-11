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
package io.contexa.contexacore.autonomous.saas.learning.prompt;

import java.util.List;

/**
 * Structural prompt presentation fingerprint derived from whitelisted formatting metadata only.
 */
public record PromptPresentationPatternProfile(
        String patternKey,
        String promptKey,
        String templateKey,
        String promptVersion,
        String transformationMode,
        boolean compressionApplied,
        String evidenceCompleteness,
        List<String> sectionSet,
        List<String> omittedSections) {

    public PromptPresentationPatternProfile {
        patternKey = normalize(patternKey);
        promptKey = normalize(promptKey);
        templateKey = normalize(templateKey);
        promptVersion = normalize(promptVersion);
        transformationMode = normalize(transformationMode);
        evidenceCompleteness = normalize(evidenceCompleteness);
        sectionSet = sectionSet == null ? List.of() : List.copyOf(sectionSet);
        omittedSections = omittedSections == null ? List.of() : List.copyOf(omittedSections);
    }

    public boolean isClassified() {
        return patternKey != null;
    }

    public static PromptPresentationPatternProfile unclassified() {
        return new PromptPresentationPatternProfile(null, null, null, null, null, false, null, List.of(), List.of());
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}