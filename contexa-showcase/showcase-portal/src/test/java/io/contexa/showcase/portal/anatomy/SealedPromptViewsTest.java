package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 2, 3.1, 3.3, 5): a step's sealed prompt as the visitor sees it,
 * from control D's view of the seal: the facts by block in the order the model reads them, each with the first of its
 * dictionary source grades; the quality ribbon counted from the same lines and the latest inspection's checks; the
 * bundle and the seal as sealed; no HTTP session identifier in any text.
 */
class SealedPromptViewsTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SESSION_ID = "0123456789ABCDEF0123456789ABCDEF";

    /** Control D's prompt facts of a seal, lines in prompt order (USER BASELINE first) as the parser gives them. */
    private static final String SEALED = """
            {"packageId": "pkg-1", "requestId": "req-1", "capturedAt": "2026-10-16T03:17:20Z",
             "packageHash": "sha256:abc", "promptBundleVersion": "2026.10.16-v20.22", "promptBundleHash": "c6b5",
             "promptBundleSelectionSource": "CONFIGURATION", "userPromptLayoutVersion": "v20-dictionary-blocks",
             "reasonCodes": [{"code": "DEVIATION_TIME", "fact": "F1"}, "APPROVAL_INVALID_MISSING"],
             "lines": [
               {"number": 2, "block": "USER_BASELINE", "factId": "B1", "label": "BaselineStatus",
                "value": "ESTABLISHED (25 learned requests)", "grades": ["LEARNED"]},
               {"number": 8, "block": "SESSION", "factId": "S1", "label": "LoginMethod",
                "value": "PASSWORD (session 0123456789ABCDEF0123456789ABCDEF)", "grades": ["HOST", "COMPUTED"]},
               {"number": 12, "block": "REQUEST", "factId": null, "label": "Subject", "value": "v1-adm-a",
                "grades": ["HOST"]},
               {"number": 13, "block": "REQUEST", "factId": "R2", "label": "Time", "value": "Wed 03:17",
                "grades": ["HOST"]},
               {"number": 17, "block": "DECISION_FACTS", "factId": "F1", "label": "DeviationsFromBaseline",
                "value": "1 of 8 compared -> time 03 seen 0 of 22 (unexpected)", "grades": ["COMPUTED"]},
               {"number": 21, "block": "PAST_RECORDS", "factId": null, "label": "PastRecordsState",
                "value": "none found (ZERO_RESULTS)", "grades": []},
               {"number": 25, "block": "UNKNOWN", "factId": null, "label": "Coverage", "value": "BUSINESS_AWARE",
                "grades": ["COMPUTED"]},
               {"number": 26, "block": "UNKNOWN", "factId": null, "label": "Unknown", "value": "not-integrated: OnCall",
                "grades": ["COMPUTED"]},
               {"number": 29, "block": "UNTRUSTED_TEXT", "factId": null, "label": "UntrustedText1",
                "value": "source=request path (requester); \\"/api/projects/GB-500/export\\"", "grades": ["UNTRUSTED"]}
             ],
             "inspection": {"verdict": "FAIL", "inspectorVersion": "prompt-inspector/17",
               "inspectedAt": "2026-10-16T03:18:00Z",
               "checks": [
                 {"code": "FACT_ACCURACY", "matched": 31, "mismatched": 1, "unverifiable": 2,
                  "mismatches": [{"block": "SESSION", "entry": "LoginMethod", "factId": "S1", "line": 8,
                    "expected": "PASSWORD+ONE_TIME_CODE",
                    "actual": "PASSWORD (session 0123456789ABCDEF0123456789ABCDEF)",
                    "reason": "the login method differs"}]},
                 {"code": "SAME_FACT", "matched": 4, "mismatched": 2, "unverifiable": 0, "mismatches": []},
                 {"code": "REASON_MATCH", "matched": 1, "mismatched": 0, "unverifiable": 1, "mismatches": []}
               ]}}""";

    @Test
    void theFactsComeByBlockInTheOrderTheModelReadsThemWithTheirSource() throws Exception {
        SealedPromptViews.FactsView view = SealedPromptViews.facts("run-0123456789ab", 1, null, JSON.readTree(SEALED));

        assertThat(view.available()).isTrue();
        assertThat(view.reason()).isNull();
        assertThat(view.blocks()).extracting(SealedPromptViews.Block::block).containsExactly("REQUEST", "SESSION",
                "USER_BASELINE", "DECISION_FACTS", "UNKNOWN", "PAST_RECORDS", "UNTRUSTED_TEXT");
        assertThat(view.blocks().get(0).facts()).extracting(SealedPromptViews.Fact::line,
                SealedPromptViews.Fact::factId, SealedPromptViews.Fact::label, SealedPromptViews.Fact::value,
                SealedPromptViews.Fact::source).containsExactly(tuple(12, null, "Subject", "v1-adm-a", "HOST"),
                tuple(13, "R2", "Time", "Wed 03:17", "HOST"));
        assertThat(view.blocks().get(1).facts().get(0).source()).as("the first grade in the grade order")
                .isEqualTo("HOST");
        assertThat(view.blocks().get(1).facts().get(0).grades()).containsExactly("HOST", "COMPUTED");
        assertThat(view.blocks().get(2).facts().get(0).source()).isEqualTo("LEARNED");
        assertThat(view.blocks().get(5).facts().get(0).source()).as("a line without a grade").isNull();
        assertThat(view.blocks().get(6).facts().get(0).source()).isEqualTo("UNTRUSTED");
        assertThat(view.bundle()).isEqualTo(new SealedPromptViews.Bundle("2026.10.16-v20.22", "c6b5",
                "CONFIGURATION", "v20-dictionary-blocks"));
    }

    @Test
    void aLineOutsideTheKnownBlocksIsKeptAfterThem() throws Exception {
        JsonNode sealed = JSON.readTree("""
                {"lines": [{"number": 1, "block": null, "label": "Note", "value": "x", "grades": []},
                           {"number": 3, "block": "SECOND_PASS", "label": "SecondPass", "value": "y",
                            "grades": ["COMPUTED"]}]}""");

        SealedPromptViews.FactsView view = SealedPromptViews.facts("run-0123456789ab", 1, null, sealed);

        assertThat(view.blocks()).extracting(SealedPromptViews.Block::block).containsExactly("SECOND_PASS", null);
    }

    @Test
    void aStepWithoutASealHasNoFactsAndSaysWhy() {
        SealedPromptViews.FactsView facts = SealedPromptViews.facts("run-0123456789ab", 2, SealedPrompts.NOT_SEALED,
                null);
        SealedPromptViews.QualityView quality = SealedPromptViews.quality(SealedPrompts.NO_STEP, null);

        assertThat(facts.available()).isFalse();
        assertThat(facts.reason()).isEqualTo("NOT_SEALED");
        assertThat(facts.blocks()).isEmpty();
        assertThat(facts.bundle()).isNull();
        assertThat(quality.available()).isFalse();
        assertThat(quality.reason()).isEqualTo("NO_STEP");
        assertThat(quality.ribbon()).isNull();
        assertThat(quality.reasonCodes()).isEmpty();
    }

    @Test
    void theRibbonCountsTheLinesAndTheInspectorsChecks() throws Exception {
        SealedPromptViews.QualityView view = SealedPromptViews.quality(null, JSON.readTree(SEALED));

        assertThat(view.available()).isTrue();
        assertThat(view.ribbon().facts()).as("the lines outside UNKNOWN").isEqualTo(7);
        assertThat(view.ribbon().withSource()).as("all but the past record state").isEqualTo(6);
        assertThat(view.ribbon().factAccuracy()).isEqualTo(new SealedPromptViews.FactAccuracy(31, 32));
        assertThat(view.ribbon().contradictions()).as("the same-fact check's mismatches").isEqualTo(2);
        assertThat(view.ribbon().unknown()).isEqualTo(2);
        assertThat(view.seal()).isEqualTo(new SealedPromptViews.Seal("pkg-1", "sha256:abc", "2026-10-16T03:17:20Z"));
        assertThat(view.reasonCodes()).containsExactly(new SealedPromptViews.ReasonCode("DEVIATION_TIME", "F1"),
                new SealedPromptViews.ReasonCode("APPROVAL_INVALID_MISSING", null));
        assertThat(view.inspection().path("verdict").asText()).isEqualTo("FAIL");
        assertThat(view.inspection().path("checks")).hasSize(3);
        assertThat(view.inspection().path("checks").get(0).path("mismatches").get(0).path("line").asInt())
                .isEqualTo(8);
    }

    @Test
    void withoutAnInspectionTheChecksAreLeftOpenNotCountedAsPassed() throws Exception {
        JsonNode sealed = JSON.readTree(SEALED.replaceFirst("\"inspection\": \\{", "\"inspection\": null, \"x\": {"));

        SealedPromptViews.QualityView view = SealedPromptViews.quality(null, sealed);

        assertThat(view.inspection()).isNull();
        assertThat(view.ribbon().factAccuracy()).isNull();
        assertThat(view.ribbon().contradictions()).isNull();
        assertThat(view.ribbon().facts()).isEqualTo(7);
        assertThat(view.ribbon().unknown()).isEqualTo(2);
    }

    @Test
    void noHttpSessionIdentifierLeavesTheViews() throws Exception {
        JsonNode sealed = JSON.readTree(SEALED);

        String facts = JSON.writeValueAsString(SealedPromptViews.facts("run-0123456789ab", 1, null, sealed));
        String quality = JSON.writeValueAsString(SealedPromptViews.quality(null, sealed));

        assertThat(facts).doesNotContain(SESSION_ID).contains("PASSWORD (session <SESSION>)");
        assertThat(quality).doesNotContain(SESSION_ID).contains("<SESSION>");
        assertThat(sealed.toString()).as("control D's answer itself is not changed").contains(SESSION_ID);
    }

    @Test
    void theViewsHaveTheContractsFields() throws Exception {
        JsonNode sealed = JSON.readTree(SEALED);
        JsonNode facts = JSON.valueToTree(SealedPromptViews.facts("run-0123456789ab", 1, null, sealed));
        JsonNode quality = JSON.valueToTree(SealedPromptViews.quality(null, sealed));

        assertThat(names(facts)).containsExactlyInAnyOrder("runId", "stepNo", "available", "reason", "bundle",
                "blocks");
        assertThat(names(facts.path("bundle"))).containsExactlyInAnyOrder("version", "hash", "selectionSource",
                "layout");
        assertThat(names(facts.path("blocks").path(0))).containsExactlyInAnyOrder("block", "facts");
        assertThat(names(facts.path("blocks").path(0).path("facts").path(0))).containsExactlyInAnyOrder("line",
                "factId", "label", "value", "source", "grades");
        assertThat(names(quality)).containsExactlyInAnyOrder("available", "reason", "bundle", "seal", "inspection",
                "reasonCodes", "ribbon");
        assertThat(names(quality.path("seal"))).containsExactlyInAnyOrder("packageId", "packageHash", "capturedAt");
        assertThat(names(quality.path("reasonCodes").path(0))).containsExactlyInAnyOrder("code", "fact");
        assertThat(names(quality.path("ribbon"))).containsExactlyInAnyOrder("facts", "withSource", "factAccuracy",
                "contradictions", "unknown");
        assertThat(names(quality.path("ribbon").path("factAccuracy"))).containsExactlyInAnyOrder("matched", "total");
        assertThat(names(quality.path("inspection"))).containsExactlyInAnyOrder("verdict", "inspectorVersion",
                "inspectedAt", "checks");
    }

    private static List<String> names(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
