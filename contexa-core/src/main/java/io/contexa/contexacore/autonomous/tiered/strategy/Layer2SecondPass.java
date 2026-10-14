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
package io.contexa.contexacore.autonomous.tiered.strategy;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.tiered.prompt.PastRecordLineValues;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * What a Layer2 second pass is given (W3-9): the first pass's verdict and the v20 prompt it sent, and the facts only
 * the second pass gathered. A first pass without a model verdict (a technical fallback) gives nothing to build on.
 */
final class Layer2SecondPass {

    static final String V20_LAYOUT = SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V20;

    /** Past record states of a search the first pass did not finish or did not run. */
    private static final Set<String> NOT_RETRIEVED = Set.copyOf(PastRecordLineValues.NOT_RETRIEVED_STATES);

    private Layer2SecondPass() {
    }

    /** The first pass as the cold path hands it over: the Layer1 assessment and what the first prompt left. */
    record FirstPass(String verdict, boolean modelVerdict, String reason, String userPrompt, String layout,
                     String pastRecordsState) {

        static FirstPass of(SecurityEvent event) {
            Map<String, Object> metadata = event != null && event.getMetadata() != null ? event.getMetadata() : Map.of();
            String verdict = null;
            String reason = null;
            boolean modelVerdict = false;
            if (metadata.get("layer1Assessment") instanceof Map<?, ?> assessment) {
                verdict = text(assessment.get("llmAction"));
                reason = text(assessment.get("reasoning"));
                modelVerdict = verdict != null
                        && Boolean.TRUE.equals(assessment.get("llmDecisionPresent"))
                        && !Boolean.TRUE.equals(assessment.get("technicalFallbackApplied"));
            }
            String userPrompt = metadata.get("userPrompt") instanceof String prompt && StringUtils.hasText(prompt)
                    ? prompt : null;
            return new FirstPass(verdict, modelVerdict, reason, userPrompt, text(metadata.get(PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION)),
                    text(metadata.get("ragRetrievalState")));
        }

        /** A model verdict on a v20 prompt the second pass can add to. */
        boolean givesASecondPass() {
            return modelVerdict && V20_LAYOUT.equals(layout) && userPrompt != null;
        }

        /** The past records this pass found when the first pass could not retrieve any. */
        List<Document> newPastRecords(List<Document> secondPassDocuments) {
            if (secondPassDocuments == null || secondPassDocuments.isEmpty() || pastRecordsState == null
                    || !NOT_RETRIEVED.contains(pastRecordsState.toUpperCase(Locale.ROOT))) {
                return List.of();
            }
            return List.copyOf(secondPassDocuments);
        }
    }

    private static String text(Object value) {
        return value != null && StringUtils.hasText(String.valueOf(value)) ? String.valueOf(value).trim() : null;
    }
}
