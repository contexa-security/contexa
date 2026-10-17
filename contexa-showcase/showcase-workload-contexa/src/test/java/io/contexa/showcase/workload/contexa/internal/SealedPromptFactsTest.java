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
 * inspection. The portal has no engine library, so control D gives these facts. N-DLV-2: the kinds of company record
 * the host looked up and the request's action family, from the sealed context, so the harness tells a condition the
 * operation does not look up. N-SRC-4: the request's action line also names the grade of its own value, as the sealed
 * context states its source, since its entry allows two (HOST and INFERRED); no other line names one.
 */
class SealedPromptFactsTest {

    private static final String PROMPT = """
            === USER BASELINE (learned) ===
            UsualLoginMethods: PASSWORD

            === DECISION FACTS ===
            [F1] DeviationsFromBaseline: 1 of 8 compared -> time 03 seen 0 of 22 (unexplained)
            """;

    /** N-SRC-4: a sealed request whose action family the core read from the protected method's name. */
    private static final String ACTION_PROMPT = """
            === USER BASELINE (learned) ===
            UsualLoginMethods: PASSWORD

            === REQUEST ===
            Time: Wed 03:17
            Action: READ (inferred from method name) GET (template /api/documents/{documentId}, method Documents.read)
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

    @Test
    void theRecordKindsAndTheActionFamilyAreTheSealedContexts() {
        Map<String, Object> view = SealedPromptFacts.view(sealed("{\"resource\": {\"actionFamily\": \"READ\"}, "
                + "\"frictionProfile\": {\"checkedRecordKinds\": [\"ASSIGNMENT\", \"TICKET\", \"ACCESS_HISTORY\", "
                + "\"TRAVEL\"]}}"), List.of(), new ObjectMapper());
        Map<String, Object> unsaid = SealedPromptFacts.view(sealed(), List.of(), new ObjectMapper());

        assertThat(view).containsEntry("actionFamily", "READ")
                .containsEntry("checkedRecordKinds", List.of("ASSIGNMENT", "TICKET", "ACCESS_HISTORY", "TRAVEL"));
        assertThat(unsaid).as("a sealed context that does not say").containsEntry("checkedRecordKinds", null)
                .containsEntry("actionFamily", null);
    }

    /**
     * N-SRC-4: the action line's entry allows HOST and INFERRED. The line names the grade of its own value, as the
     * sealed context states its source, so an action read from the method name is INFERRED, not the entry's first
     * grade; the lines of one grade name none of their own and keep their entries' grades.
     */
    @Test
    void anActionReadFromTheMethodNameIsInferredNotTheEntrysFirstGrade() {
        Map<String, Object> view = SealedPromptFacts.view(sealed(ACTION_PROMPT, "{\"resource\": {\"actionFamily\": "
                + "\"READ\", \"actionFamilySource\": \"inferred:protectableMethod\"}}"), List.of(), new ObjectMapper());

        List<?> lines = (List<?>) view.get("lines");
        assertThat(lines).hasSize(3);
        assertThat(map(lines.get(2))).containsEntry("block", "REQUEST").containsEntry("label", "Action")
                .containsEntry("grades", List.of("HOST", "INFERRED")).containsEntry("source", "INFERRED");
        assertThat(map(lines.get(0))).as("a line of one grade").containsEntry("label", "UsualLoginMethods")
                .containsEntry("grades", List.of("LEARNED")).doesNotContainKey("source");
        assertThat(map(lines.get(1))).as("a request line of one grade").containsEntry("label", "Time")
                .containsEntry("grades", List.of("COMPUTED")).doesNotContainKey("source");
    }

    /** N-SRC-4: an action the host declared is HOST, as its sealed context states. */
    @Test
    void anActionTheHostDeclaredIsHost() {
        Map<String, Object> action = action(ACTION_PROMPT.replace("(inferred from method name)", "(declared)"),
                "{\"resource\": {\"actionFamily\": \"READ\", "
                        + "\"actionFamilySource\": \"host:protectableActionFamily\"}}");

        assertThat(action).containsEntry("grades", List.of("HOST", "INFERRED")).containsEntry("source", "HOST");
    }

    /**
     * N-SRC-4: an action whose sealed context states no source (the value says 'source not stated') or a grade its
     * entry does not declare names no source of its own: null, never the entry's first grade.
     */
    @Test
    void anActionWhoseSealStatesNoGradeItsEntryDeclaresHasNoSource() {
        String unstated = ACTION_PROMPT.replace("READ (inferred from method name)", "UNKNOWN (source not stated)");

        assertThat(action(unstated, null)).as("no sealed context").containsEntry("source", null);
        assertThat(action(unstated, "{\"resource\": {\"actionFamily\": \"UNKNOWN\"}}")).as("no source stated")
                .containsEntry("source", null);
        assertThat(action(unstated, "{\"resource\": {\"actionFamilySource\": \"computed:riskScore\"}}"))
                .as("a grade the entry does not declare").containsEntry("source", null);
    }

    /** N-SRC-4: the action line of the view of a seal with this user prompt and sealed context. */
    /**
     * N-SRC-5: the other lines whose entries declare host or computed name the grade of their own value: the
     * authorization effect by the stage it states (the core's method authorization computed, a host stamp host, none
     * unstated), the two session fields the host alone gives host, and the sensitive access count, which the seal
     * does not say the source of, none.
     */
    @Test
    void theLinesOfTwoGradesNameTheGradeOfTheirOwnValue() {
        String prompt = """
                === SESSION ===
                ConcurrentSessions: 2 concurrent sessions
                PasswordAge: 40 days since the password changed
                RecentSensitiveAccess: 3 recent sensitive accesses

                === DECISION FACTS ===
                [F1] AuthorizationEffect: %s
                """;

        assertThat(line(prompt.formatted("ALLOW (METHOD_AUTHORIZATION_BEFORE_EXECUTION)"), "AuthorizationEffect"))
                .containsEntry("grades", List.of("HOST", "COMPUTED")).containsEntry("source", "COMPUTED");
        assertThat(line(prompt.formatted("ALLOW by policy P-7 (METHOD_AUTHORIZATION_CHECK)"), "AuthorizationEffect"))
                .containsEntry("source", "COMPUTED");
        assertThat(line(prompt.formatted("DENY (BRIDGE_AUTHORIZATION_STAMP)"), "AuthorizationEffect"))
                .containsEntry("source", "HOST");
        assertThat(line(prompt.formatted("method failed with NOT_FOUND after authorization"), "AuthorizationEffect"))
                .as("no stage stated").containsEntry("source", null);
        String any = prompt.formatted("ALLOW (METHOD_AUTHORIZATION_CHECK)");
        assertThat(line(any, "ConcurrentSessions")).containsEntry("source", "HOST");
        assertThat(line(any, "PasswordAge")).containsEntry("source", "HOST");
        assertThat(line(any, "RecentSensitiveAccess")).containsEntry("grades", List.of("HOST", "COMPUTED"))
                .containsEntry("source", null);
    }

    private static Map<String, Object> line(String userPrompt, String label) {
        Map<String, Object> view = SealedPromptFacts.view(sealed(userPrompt, null), List.of(), new ObjectMapper());
        return ((List<?>) view.get("lines")).stream().map(SealedPromptFactsTest::map)
                .filter(line -> label.equals(line.get("label"))).findFirst().orElseThrow();
    }

    private static Map<String, Object> action(String userPrompt, String canonicalContextJson) {
        Map<String, Object> view = SealedPromptFacts.view(sealed(userPrompt, canonicalContextJson), List.of(),
                new ObjectMapper());
        return ((List<?>) view.get("lines")).stream().map(SealedPromptFactsTest::map)
                .filter(line -> "Action".equals(line.get("label"))).findFirst().orElseThrow();
    }

    private static PromptInspectionRecord record(long id, PromptInspectionVerdict verdict,
                                                 List<PromptInspectionCheckResult> checks, String at) {
        return new PromptInspectionRecord(id, new PromptInspectionResult("pkg-1", "prompt-inspector/17", "dict-1",
                "v20-dictionary-blocks", verdict, checks, null), PromptInspectionTrigger.AUTO, Instant.parse(at));
    }

    private static SealedEvidencePackage sealed() {
        return sealed(null);
    }

    private static SealedEvidencePackage sealed(String canonicalContextJson) {
        return sealed(PROMPT, canonicalContextJson);
    }

    private static SealedEvidencePackage sealed(String userPrompt, String canonicalContextJson) {
        return SealedEvidencePackage.builder()
                .packageId("pkg-1")
                .correlationId("req-1")
                .capturedAt(Instant.parse("2026-10-15T20:21:17Z"))
                .packageHash("sha256:abc")
                .userPromptText(userPrompt)
                .promptExecutionMetadataJson("{\"governanceDescriptor\":{\"promptBundleVersion\":\"2026.10.16-v20.22\","
                        + "\"promptBundleHash\":\"c6b5\",\"promptBundleSelectionSource\":\"CONFIGURATION\","
                        + "\"userPromptLayoutVersion\":\"v20-dictionary-blocks\"}}")
                .decisionJson("{\"action\":\"CHALLENGE\",\"reasonCodes\":[{\"code\":\"DEVIATION_TIME\",\"fact\":\"F1\"}]}")
                .canonicalContextJson(canonicalContextJson)
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
