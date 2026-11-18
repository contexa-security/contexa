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

import java.util.List;
import java.util.Map;

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

    /**
     * N1: the code VERIFIED_SIGNAL cites the VerifiedSignal line and holds on it; no other code may cite that line, and
     * the code holds on no other line. The product version's system text names it with the line it cites.
     */
    @Test
    void theCodeOfAVerifiedSignalCitesItsLineAndNoOtherCodeDoes() {
        InspectionGolden.Render verified = SecurityDecisionV1BundleTest.render(MeasuredVariant.RECORD_SIMILAR,
                context -> signal(context, V1LineValues.TRUSTED_SIGNAL_SOURCE));
        SecurityDecisionFactChecks.DrawnPrompt drawn = SecurityDecisionFactChecks.DrawnPrompt.of(verified.userPrompt());
        String line = drawn.lineIds().entrySet().stream()
                .filter(entry -> entry.getValue().equals("DECISION_FACTS.VerifiedSignal"))
                .map(Map.Entry::getKey).findFirst().orElseThrow();
        String other = drawn.lineIds().keySet().stream().filter(id -> !id.equals(line)).findFirst().orElseThrow();

        assertThat(outcome(verified, drawn, "VERIFIED_SIGNAL", line)).isEqualTo(SecurityDecisionFactChecks.Outcome.MATCH);
        assertThat(outcome(verified, drawn, "VERIFIED_SIGNAL", other))
                .isEqualTo(SecurityDecisionFactChecks.Outcome.MISMATCH);
        for (String code : List.of("THREAT_MATCH", "MATERIAL_CONTRADICTION", "AUTHORIZATION_CONFLICT",
                "CLIENT_SIGNAL_TAMPERING")) {
            assertThat(outcome(verified, drawn, code, line)).as(code).isEqualTo(SecurityDecisionFactChecks.Outcome.MISMATCH);
        }
        assertThat(SecurityDecisionOutputContractV4.citedLines()).containsEntry("VERIFIED_SIGNAL", List.of("VerifiedSignal"));
        assertThat(verified.systemPrompt()).contains("- VERIFIED_SIGNAL: a signal the server itself confirmed for this"
                + " request; VerifiedSignal\n");
    }

    private static SecurityDecisionFactChecks.Outcome outcome(InspectionGolden.Render render,
                                                              SecurityDecisionFactChecks.DrawnPrompt drawn, String code,
                                                              String fact) {
        return SecurityDecisionAnswerChecks.reasonFindings(render.used(), drawn,
                List.of(new SecurityDecisionOutputContract.Citation(code, fact))).get(0).outcome();
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
