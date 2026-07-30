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
package io.contexa.contexacore.std.pipeline.processor;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityDecisionOutputParserTest {

    private final SecurityDecisionOutputParser parser = new SecurityDecisionOutputParser();

    @Test
    void parseShouldUseValidJsonValues() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-valid");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "action": "ALLOW",
                  "confidence": 0.82,
                  "riskScore": 0.18,
                  "reasoning": "Known session context supports the read request.",
                  "mitre": "UNKNOWN",
                  "evidenceRefs": ["session"]
                }
                """, context);

        assertThat(result.getAction()).isEqualTo("ALLOW");
        assertThat(result.getConfidence()).isEqualTo(0.82d);
        assertThat(result.getRiskScore()).isEqualTo(0.18d);
        assertThat(result.getReasoning()).isEqualTo("Known session context supports the read request.");
        assertThat(context.getMetadata("securityDecisionOutputRepairApplied", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("NONE");
        assertThat(context.getMetadata("securityDecisionSyntheticDefaultFields", List.class)).isEmpty();
    }

    @Test
    void parseShouldPreserveBlankOptionalScoresAndMetadata() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-score-string");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "action": "ALLOW",
                  "confidence": "0.9",
                  "mitre": "",
                  "reasoning": "The request matches the currently observed read context.",
                  "riskScore": ""
                }
                """, context);

        assertThat(result.getAction()).isEqualTo("ALLOW");
        assertThat(result.getConfidence()).isEqualTo(0.9d);
        assertThat(result.getRiskScore()).isNull();
        assertThat(result.getMitre()).isNull();
        assertThat(context.getMetadata("securityDecisionOutputRepairApplied", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionSyntheticDefaultFields", List.class)).isEmpty();
    }

    @Test
    void parseShouldRecoverCoreFieldsFromTruncatedJson() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-truncated");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "action": "ALLOW",
                  "confidence": 0.9,
                  "mitre": "",
                  "reasoning": "The current request has known identity and low privilege scope.",
                  "riskScore":
                """, context);

        assertThat(result.getAction()).isEqualTo("ALLOW");
        assertThat(result.getReasoning()).isEqualTo("The current request has known identity and low privilege scope.");
        assertThat(result.getRiskScore()).isNull();
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("TRUNCATED_JSON");
        assertThat(context.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class)).isFalse();
    }

    @Test
    void parseShouldFailClosedWhenActionIsMissing() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-missing-action");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "reasoning": "The model omitted the required action field.",
                  "riskScore": 0.2
                }
                """, context);

        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(result.getReasoning()).isEqualTo("The model omitted the required action field.");
        assertThat(result.getRiskScore()).isEqualTo(0.2d);
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isFalse();
        assertThat(context.getMetadata("syntheticSecurityDecisionApplied", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionFallbackAction", String.class)).isEqualTo("CHALLENGE");
        assertThat(context.getMetadata("securityDecisionFallbackReason", String.class))
                .isEqualTo("ACTION_MISSING");
        assertThat(context.getMetadata("securityDecisionSyntheticDefaultFields", List.class))
                .isEmpty();
    }

    @Test
    void parseShouldDistinguishInvalidActionFromMissingAction() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-invalid-action");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "action": "RETRY_LATER",
                  "reasoning": "The model returned an unsupported action.",
                  "riskScore": 0.4,
                  "confidence": 0.5,
                  "mitre": "UNKNOWN",
                  "evidenceRefs": ["session"]
                }
                """, context);

        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(context.getMetadata("securityDecisionFallbackReason", String.class))
                .isEqualTo("ACTION_FORMAT_INVALID");
    }

    @Test
    void parseShouldNormalizeOneDecoratedCanonicalAction() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-decorated-action");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "action": "ALLOW_WITH_ADDITIONAL_CONTEXT",
                  "reasoning": "Current authorization and resource facts support access."
                }
                """, context);

        assertThat(result.getAction()).isEqualTo("ALLOW");
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionOutputRepairApplied", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionActionCandidate", String.class))
                .isEqualTo("ALLOW_WITH_ADDITIONAL_CONTEXT");
    }

    @Test
    void parseShouldFailClosedForAmbiguousDecoratedActions() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-ambiguous-action");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "action": "ALLOW_OR_CHALLENGE",
                  "reasoning": "The model returned more than one action."
                }
                """, context);

        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionFallbackReason", String.class))
                .isEqualTo("ACTION_FORMAT_INVALID");
    }

    @Test
    void parseShouldFailClosedForEmptyResponse() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-empty");

        SecurityDecisionResponseLite result = parser.parse("", context);

        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(result.getReasoning()).isNull();
        assertThat(result.getRiskScore()).isNull();
        assertThat(result.getConfidence()).isNull();
        assertThat(result.getMitre()).isNull();
        assertThat(result.getEvidenceRefs()).isEmpty();
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("EMPTY_RESPONSE");
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionSyntheticDefaultFields", List.class))
                .isEmpty();
    }

    @Test
    void parseShouldPreserveModelUnavailableFailureForEmptyRawResult() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-model-unavailable");
        context.addMetadata("securityDecisionParseFailureCategory", "MODEL_UNAVAILABLE");

        SecurityDecisionResponseLite result = parser.parse("", context);

        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("MODEL_UNAVAILABLE");
        assertThat(context.getMetadata("securityDecisionFallbackAction", String.class)).isEqualTo("CHALLENGE");
    }
    @Test
    void parseShouldPreserveDetailedOfficialEvidenceRefs() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-detailed-refs");

        SecurityDecisionResponseLite result = parser.parse("""
                {
                  "action": "CHALLENGE",
                  "confidence": 0.64,
                  "riskScore": 0.62,
                  "reasoning": "fresh verification is required before allowing access; challenge is safer than allow with limited baseline",
                  "mitre": "UNKNOWN",
                  "evidenceRefs": ["verification.required", "mfa.freshness.stale", "authorization.policy.allow_after_verification", "baseline.status.insufficient", "baseline.confidence.low"]
                }
                """, context);

        assertThat(result.getEvidenceRefs()).contains(
                "verification.required",
                "mfa.freshness.stale",
                "authorization.policy.allow_after_verification",
                "baseline.status.insufficient",
                "baseline.confidence.low");
        assertThat(result.getEvidenceRefs()).doesNotContain("baseline");
        assertThat(context.getMetadata("securityDecisionEvidenceRefsPresent", Boolean.class)).isTrue();
    }
}
