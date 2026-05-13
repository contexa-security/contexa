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
                  "mitre": "UNKNOWN"
                }
                """, context);

        assertThat(result.getAction()).isEqualTo("ALLOW");
        assertThat(result.getConfidence()).isEqualTo(0.82d);
        assertThat(result.getRiskScore()).isEqualTo(0.18d);
        assertThat(result.getReasoning()).isEqualTo("Known session context supports the read request.");
        assertThat(context.getMetadata("securityDecisionOutputRepairApplied", Boolean.class)).isFalse();
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("NONE");
    }

    @Test
    void parseShouldRepairStringOrBlankAuxiliaryScores() {
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
        assertThat(result.getRiskScore()).isEqualTo(0.20d);
        assertThat(result.getMitre()).isEqualTo("UNKNOWN");
        assertThat(context.getMetadata("securityDecisionOutputRepairApplied", Boolean.class)).isTrue();
        assertThat(context.getMetadata("securityDecisionOutputRepairFields", List.class))
                .contains("riskScore", "mitre");
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
        assertThat(result.getRiskScore()).isEqualTo(0.20d);
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
    }

    @Test
    void parseShouldFailClosedForEmptyResponse() {
        PipelineExecutionContext context = new PipelineExecutionContext("parse-empty");

        SecurityDecisionResponseLite result = parser.parse("", context);

        assertThat(result.getAction()).isEqualTo("CHALLENGE");
        assertThat(result.getReasoning()).isEqualTo("Model output was incomplete; challenge is required.");
        assertThat(result.getRiskScore()).isEqualTo(0.55d);
        assertThat(context.getMetadata("securityDecisionParseFailureCategory", String.class)).isEqualTo("EMPTY_RESPONSE");
        assertThat(context.getMetadata("llmDecisionPresent", Boolean.class)).isFalse();
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
}
