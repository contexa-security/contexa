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

public class SecurityContextQualityUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        String missingKnowledgeSection = template.buildExplicitMissingKnowledgeSection(context.getCanonicalSecurityContext());
        String baselineGapSupport = template.buildSupportingPromptBlock(
                "BaselineGapSupport",
                template.buildBaselineGapSection(
                        context.getBaselineStatus(),
                        context.getLearningContextEvidence()
                )
        );

        if (missingKnowledgeSection == null && baselineGapSupport != null) {
            section.append("\n=== EXPLICIT MISSING KNOWLEDGE ===\n");
        }

        template.appendIfPresent(section, missingKnowledgeSection);
        template.appendIfPresent(section, baselineGapSupport);
        return section.toString();
    }
}
