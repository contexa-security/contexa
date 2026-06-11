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

public class SecuritySessionUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String sessionNarrativeSection = template.buildSessionNarrativeContextSection(context.getCanonicalSecurityContext());
        String sessionTimelineSupport = template.buildSupportingPromptBlock(
                "SessionTimelineSupport",
                template.buildSessionTimelineSection(
                        context.getSessionContext(),
                        context.getBehaviorAnalysis()
                )
        );
        String sessionDeviceChangeSupport = template.buildSupportingPromptBlock(
                "SessionDeviceChangeSupport",
                template.buildSessionDeviceChangeSection(context.getBehaviorAnalysis())
        );
        String historicalComparableSupport = null;
        boolean hasTypedComparables =
                context.getLearningContextEvidence() != null
                        && context.getLearningContextEvidence().hasComparableEvidence();
        if (hasTypedComparables) {
            historicalComparableSupport = template.buildSupportingPromptBlock(
                    "HistoricalComparableEvents",
                    template.buildSimilarEventsSection(
                            context.getBehaviorAnalysis(),
                            context.getDetectedPatterns()
                    )
            );
        }

        if (sessionNarrativeSection == null
                && (sessionTimelineSupport != null
                || sessionDeviceChangeSupport != null
                || historicalComparableSupport != null)) {
            section.append("\n=== SESSION NARRATIVE CONTEXT ===\n");
        }

        template.appendIfPresent(section, sessionNarrativeSection);
        template.appendIfPresent(section, sessionTimelineSupport);
        template.appendIfPresent(section, sessionDeviceChangeSupport);
        template.appendIfPresent(section, historicalComparableSupport);
        return section.toString();
    }
}
