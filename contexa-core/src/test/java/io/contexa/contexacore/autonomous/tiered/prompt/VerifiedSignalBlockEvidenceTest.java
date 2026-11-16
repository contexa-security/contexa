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
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * K36 (decision D5): a signal the server itself confirmed, drawn on the VerifiedSignal line, is decisive evidence a BLOCK
 * may rest on, so the response check does not ask again for a BLOCK of such a request; a signal of any other source is
 * a requester's claim and leaves the BLOCK unsupported, as before.
 */
class VerifiedSignalBlockEvidenceTest {

    @Test
    void aBlockOnASignalTheServerConfirmedIsNotABlockWithoutEvidence() {
        InspectionGolden.Render verified = SecurityDecisionV1BundleTest.render(SecurityDecisionPromptBundles.V1,
                context -> signal(context, V1LineValues.TRUSTED_SIGNAL_SOURCE));
        InspectionGolden.Render claimed = SecurityDecisionV1BundleTest.render(SecurityDecisionPromptBundles.V1,
                context -> signal(context, "REQUEST_HEADER"));
        InspectionGolden.Render none = SecurityDecisionV1BundleTest.render(SecurityDecisionPromptBundles.V1, context -> {
        });

        assertThat(verified.userPrompt()).contains("VerifiedSignal: CONFIRMED_ACCOUNT_TAKEOVER");
        assertThat(claimed.userPrompt()).doesNotContain("VerifiedSignal:");
        assertThat(violation(verified, "BLOCK")).isNull();
        assertThat(violation(claimed, "BLOCK")).isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        assertThat(violation(none, "BLOCK")).isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
        // The signal permits a BLOCK; it does not ask for one.
        assertThat(violation(verified, "CHALLENGE")).isEqualTo(violation(none, "CHALLENGE"));
    }

    private static void signal(CanonicalSecurityContext context, String source) {
        CanonicalSecurityContext.Intent intent = context.getIntent() != null ? context.getIntent()
                : new CanonicalSecurityContext.Intent();
        intent.setAnomalySignal("CONFIRMED_ACCOUNT_TAKEOVER: the official verification confirmed malicious activity");
        intent.setAnomalySignalSource(source);
        context.setIntent(intent);
    }

    private static String violation(InspectionGolden.Render render, String action) {
        CanonicalSecurityContext context = render.used();
        return SecurityDecisionFactChecks.boundaryViolation(context, context.getConclusionFacts(),
                SecurityDecisionFactChecks.DrawnPrompt.of(render.userPrompt()), action);
    }
}
