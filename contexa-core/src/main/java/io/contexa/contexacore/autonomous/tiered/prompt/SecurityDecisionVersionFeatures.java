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

import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * What a version of the security decision prompt asks the engine to do besides drawing its text (plan 6-2): the
 * effects of the parts it draws. The functions of the measured v1.0 variants are these effects of the prepared parts
 * (decision D6), so a version, not a bundle, turns them on.
 *
 * @param decisionRules          the version draws the prepared decision rules
 * @param conclusionLines        the user prompt states the core's conclusions the decision rules read
 *                               (DeviationsExplained, PolicySatisfied)
 * @param fallbackOnViolation    an answer that still breaks a decision rule after the retry is replaced by the action
 *                               the rule names, and it is asked again as the rules ask
 * @param similarCases           the similarity search adds its similar cases to the exact past record lookup
 * @param agentVariesSystemText  a part the version draws has its own text for an agent's request
 */
public record SecurityDecisionVersionFeatures(boolean decisionRules, boolean conclusionLines,
                                              boolean fallbackOnViolation, boolean similarCases,
                                              boolean agentVariesSystemText) {

    /** The effect of the decision rules: the conclusion lines in the user prompt. */
    public static final String CONCLUSION_LINES = "conclusion-lines";
    /** The effect of the decision rules: the action a broken rule names replaces the answer after the retry. */
    public static final String FALLBACK_ON_VIOLATION = "fallback-on-violation";
    /** The effect of the similar case reading: the similarity search runs. */
    public static final String SIMILAR_CASES = "similar-cases";

    static final String DECISION_RULES_PART = "decision-rules";

    /** The features of each version, by its content hash: worked out once, as a version does not change. */
    private static final Map<String, SecurityDecisionVersionFeatures> BY_VERSION = new ConcurrentHashMap<>();

    /** The features of the version. */
    public static SecurityDecisionVersionFeatures of(AssembledPrompt version) {
        return BY_VERSION.computeIfAbsent(version.contentHash(), hash -> {
            Set<String> effects = version.effects();
            boolean agentVaries = version.drawnParts(AssembledPrompt.JUDGMENT,
                            Set.of(SecurityDecisionPromptDocument.AGENT_REQUEST)).stream()
                    .anyMatch(part -> part.whenText().containsKey(SecurityDecisionPromptDocument.AGENT_REQUEST));
            boolean rules = version.systemPart(DECISION_RULES_PART).filter(part -> !part.prepared()).isPresent();
            return new SecurityDecisionVersionFeatures(rules, effects.contains(CONCLUSION_LINES),
                    effects.contains(FALLBACK_ON_VIOLATION), effects.contains(SIMILAR_CASES), agentVaries);
        });
    }
}
