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

import java.util.ArrayList;
import java.util.List;
import io.contexa.contexacore.autonomous.learning.evidence.LearningContextEvidence;

public class SecurityCanonicalContextUserSectionBuilder implements SecurityPromptSectionBuilder {

    @Override
    public String build(SecurityDecisionPromptSections template, SecurityPromptBuildContext context) {
        StringBuilder section = new StringBuilder();
        template.appendIfPresent(section, template.buildBridgeResolutionSection(context.getCanonicalSecurityContext()));
        String coverageSection = template.buildCoverageSection(context);
        template.appendIfPresent(section, reconcileCoverageSection(coverageSection, context));
        return section.toString();
    }

    private String reconcileCoverageSection(String coverageSection, SecurityPromptBuildContext context) {
        if (coverageSection == null || coverageSection.isBlank()) {
            return coverageSection;
        }

        List<String> reconciled = new ArrayList<>();
        boolean hasResolvedAuthorizationEffect = context != null
                && context.getCanonicalSecurityContext() != null
                && context.getCanonicalSecurityContext().getAuthorization() != null
                && context.getCanonicalSecurityContext().getAuthorization().getAuthorizationEffect() != null
                && !context.getCanonicalSecurityContext().getAuthorization().getAuthorizationEffect().isBlank();
        LearningContextEvidence learningEvidence = context != null ? context.getLearningContextEvidence() : null;
        boolean personalBaselineEstablished = learningEvidence != null
                && learningEvidence.personalBaseline() != null
                && learningEvidence.personalBaseline().established();
        boolean supportingBaselineAvailable = learningEvidence != null
                && learningEvidence.supportingBaseline() != null
                && learningEvidence.supportingBaseline().available();

        for (String line : coverageSection.split("\\R")) {
            if (hasResolvedAuthorizationEffect
                    && line.equals("- Bridge missing context: AUTHORIZATION_EFFECT.")) {
                continue;
            }
            if (personalBaselineEstablished
                    && line.equals("- Observed work pattern is missing; comparisons against previously seen resources or action families remain limited.")) {
                continue;
            }
            if (!personalBaselineEstablished
                    && supportingBaselineAvailable
                    && line.equals("- Observed work pattern is missing; comparisons against previously seen resources or action families remain limited.")) {
                reconciled.add("- Canonical observed-work coverage is incomplete; supporting baseline history is reference-only and never replaces an established personal pattern.");
                continue;
            }
            if (personalBaselineEstablished
                    && line.equals("- Personal work profile is missing; do not claim the current request matches long-term normal work patterns.")) {
                continue;
            }
            reconciled.add(line);
        }
        return String.join("\n", reconciled);
    }
}
