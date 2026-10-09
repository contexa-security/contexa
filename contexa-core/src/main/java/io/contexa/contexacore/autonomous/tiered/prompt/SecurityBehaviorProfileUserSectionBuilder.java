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

public class SecurityBehaviorProfileUserSectionBuilder implements SecurityPromptSectionBuilder {

    private static final String WORK_PROFILE_EVIDENCE_STATE_LABEL = "WorkProfileEvidenceState:";

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String observedWorkPatternSection = template.buildObservedWorkPatternContextSection(context.getCanonicalSecurityContext());
        String personalWorkProfileSection = template.buildPersonalWorkProfileContextSection(context);
        // The work-profile section already states WorkProfileEvidenceState; repeating a value derived from the
        // baseline here would give the same label two different values in one prompt.
        boolean workProfileStateStated = personalWorkProfileSection != null
                && personalWorkProfileSection.contains(WORK_PROFILE_EVIDENCE_STATE_LABEL);
        String historicalBaselineSupport = template.buildSupportingPromptBlock(
                        "HistoricalBaselineSupport",
                        template.buildUserProfileNarrative(
                                context.getEvent(),
                                context.getDetectedPatterns(),
                                context.getBehaviorAnalysis(),
                                context.getBaselineStatus(),
                                !workProfileStateStated
                        )
                );

        template.appendIfPresent(section, observedWorkPatternSection);
        if (personalWorkProfileSection == null && historicalBaselineSupport != null) {
            section.append("\n=== PERSONAL WORK PROFILE ===\n");
        }
        template.appendIfPresent(section, personalWorkProfileSection);
        template.appendIfPresent(section, historicalBaselineSupport);
        return section.toString();
    }

}




