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
 * K36 (decision D5): a signal the server itself confirmed, drawn on the VerifiedSignal line of the product version and
 * of a version with the decision rules, is decisive evidence a BLOCK may rest on, so the response check does not ask
 * again for a BLOCK of such a request, and a version that replaces an answer breaking a rule keeps that BLOCK. A signal
 * of any other source is a requester's claim and leaves the BLOCK unsupported, as before.
 */
class VerifiedSignalBlockEvidenceTest {

    @Test
    void aBlockOnASignalTheServerConfirmedIsNotABlockWithoutEvidence() {
        for (MeasuredVariant variant : new MeasuredVariant[] {MeasuredVariant.RECORD_SIMILAR,
                MeasuredVariant.FALLBACK_SIMILAR}) {
            InspectionGolden.Render verified = SecurityDecisionV1BundleTest.render(variant,
                    context -> signal(context, V1LineValues.TRUSTED_SIGNAL_SOURCE));
            InspectionGolden.Render claimed = SecurityDecisionV1BundleTest.render(variant,
                    context -> signal(context, "REQUEST_HEADER"));
            InspectionGolden.Render none = SecurityDecisionV1BundleTest.render(variant, context -> {
            });

            assertThat(verified.userPrompt()).as(variant.name()).contains("VerifiedSignal: CONFIRMED_ACCOUNT_TAKEOVER");
            assertThat(claimed.userPrompt()).as(variant.name()).doesNotContain("VerifiedSignal:");
            assertThat(violation(verified, "BLOCK")).as(variant.name()).isNull();
            assertThat(violation(claimed, "BLOCK")).as(variant.name())
                    .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
            assertThat(violation(none, "BLOCK")).as(variant.name())
                    .isEqualTo(SecurityDecisionFactChecks.BLOCK_WITHOUT_EVIDENCE);
            // The signal permits a BLOCK; it does not ask for one, and it is no reason to ask for an ALLOW.
            assertThat(violation(verified, "CHALLENGE")).as(variant.name()).isNull();
            assertThat(violation(verified, "ESCALATE")).as(variant.name()).isNull();
        }
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
