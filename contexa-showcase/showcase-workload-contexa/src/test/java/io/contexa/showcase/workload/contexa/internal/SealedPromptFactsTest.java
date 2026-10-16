package io.contexa.showcase.workload.contexa.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheckResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionOutcome;
import io.contexa.contexacore.verification.inspection.PromptInspectionRecord;
import io.contexa.contexacore.verification.inspection.PromptInspectionResult;
import io.contexa.contexacore.verification.inspection.PromptInspectionTrigger;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W6-1 (P6-CHANGE-2): the sealed prompt of a decision as the harness reads it, line by line through the OSS prompt
 * parser, with the dictionary source grade of each line, the bundle the seal names, the reason codes and the latest
 * inspection. The portal has no engine library, so control D gives these facts.
 */
class SealedPromptFactsTest {

    private static final String PROMPT = """
            === USER BASELINE (learned) ===
            UsualLoginMethods: PASSWORD

            === DECISION FACTS ===
            [F1] DeviationsFromBaseline: 1 of 8 compared -> time 03 seen 0 of 22 (unexplained)
            """;

    @Test
    void theSealedPromptIsGivenLineByLineWithItsSourceGrades() {
        Map<String, Object> view = SealedPromptFacts.view(sealed(), List.of(), new ObjectMapper());

        assertThat(view).containsEntry("packageId", "pkg-1").containsEntry("requestId", "req-1")
                .containsEntry("capturedAt", "2026-10-15T20:21:17Z").containsEntry("packageHash", "sha256:abc");
        List<?> lines = (List<?>) view.get("lines");
        assertThat(lines).hasSize(2);
        assertThat(map(lines.get(0))).containsEntry("number", 2).containsEntry("block", "USER_BASELINE")
                .containsEntry("factId", null).containsEntry("label", "UsualLoginMethods")
                .containsEntry("value", "PASSWORD").containsEntry("grades", List.of("LEARNED"));
        assertThat(map(lines.get(1))).containsEntry("number", 5).containsEntry("block", "DECISION_FACTS")
                .containsEntry("factId", "F1").containsEntry("label", "DeviationsFromBaseline")
                .containsEntry("grades", List.of("COMPUTED"));
    }

    @Test
    void theBundleAndTheReasonCodesAreTheSealedOnes() {
        Map<String, Object> view = SealedPromptFacts.view(sealed(), List.of(), new ObjectMapper());

        assertThat(view).containsEntry("promptBundleVersion", "2026.10.16-v20.22")
                .containsEntry("promptBundleHash", "c6b5").containsEntry("promptBundleSelectionSource", "CONFIGURATION")
                .containsEntry("userPromptLayoutVersion", "v20-dictionary-blocks");
        assertThat(list(view.get("reasonCodes"))).containsExactly(Map.of("code", "DEVIATION_TIME", "fact", "F1"));
        assertThat(view).containsEntry("inspection", null);
    }

    @Test
    void theLatestInspectionIsGivenWithItsChecksAndMismatches() {
        PromptInspectionFinding mismatch = PromptInspectionFinding.builder("FACT_ACCURACY", PromptInspectionOutcome.MISMATCH)
                .block("DECISION FACTS").entry("DeviationsFromBaseline").factId("F1").lineNumber(5)
                .expected("time 03 seen 1 of 22").actual("time 03 seen 0 of 22").reason("the count differs").build();
        PromptInspectionRecord older = record(1L, PromptInspectionVerdict.PASS, List.of(), "2026-10-15T20:22:00Z");
        PromptInspectionRecord latest = record(2L, PromptInspectionVerdict.FAIL, List.of(
                new PromptInspectionCheckResult("FACT_ACCURACY", 3, 1, 1, List.of(mismatch), List.of())),
                "2026-10-15T20:30:00Z");

        Map<String, Object> view = SealedPromptFacts.view(sealed(), List.of(older, latest), new ObjectMapper());

        Map<String, Object> inspection = map(view.get("inspection"));
        assertThat(inspection).containsEntry("verdict", "FAIL").containsEntry("inspectorVersion", "prompt-inspector/17")
                .containsEntry("inspectedAt", "2026-10-15T20:30:00Z");
        Map<String, Object> check = map(list(inspection.get("checks")).get(0));
        assertThat(check).containsEntry("code", "FACT_ACCURACY").containsEntry("matched", 3)
                .containsEntry("mismatched", 1).containsEntry("unverifiable", 1);
        Map<String, Object> finding = map(list(check.get("mismatches")).get(0));
        assertThat(finding).containsEntry("factId", "F1").containsEntry("line", 5)
                .containsEntry("expected", "time 03 seen 1 of 22").containsEntry("actual", "time 03 seen 0 of 22");
    }

    private static PromptInspectionRecord record(long id, PromptInspectionVerdict verdict,
                                                 List<PromptInspectionCheckResult> checks, String at) {
        return new PromptInspectionRecord(id, new PromptInspectionResult("pkg-1", "prompt-inspector/17", "dict-1",
                "v20-dictionary-blocks", verdict, checks, null), PromptInspectionTrigger.AUTO, Instant.parse(at));
    }

    private static SealedEvidencePackage sealed() {
        return SealedEvidencePackage.builder()
                .packageId("pkg-1")
                .correlationId("req-1")
                .capturedAt(Instant.parse("2026-10-15T20:21:17Z"))
                .packageHash("sha256:abc")
                .userPromptText(PROMPT)
                .promptExecutionMetadataJson("{\"governanceDescriptor\":{\"promptBundleVersion\":\"2026.10.16-v20.22\","
                        + "\"promptBundleHash\":\"c6b5\",\"promptBundleSelectionSource\":\"CONFIGURATION\","
                        + "\"userPromptLayoutVersion\":\"v20-dictionary-blocks\"}}")
                .decisionJson("{\"action\":\"CHALLENGE\",\"reasonCodes\":[{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"}]}")
                .build();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value) {
        return (List<Object>) value;
    }
}
