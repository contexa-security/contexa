package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two hour lists of the usual-behaviour card are read from the prompt the engine received, as it wrote them (work
 * 10 of docs/showcase/화면설계서-v2-구현계획.md). The prompt below is a real decision of the 2026-10-06 measurement.
 */
class BaselineEvidenceTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void bothHourListsAreReadAsTheEngineReceivedThem() throws Exception {
        String prompt = userPrompt("a3s-challenge");

        assertThat(BaselineEvidence.normalAccessHours(prompt)).as("the work profile's most frequent hours")
                .containsExactly(10, 11, 13, 15, 16, 17);
        assertThat(BaselineEvidence.observedHours(prompt)).as("every hour of the learned history, in prompt order")
                .containsExactly(10, 14, 15, 16, 17, 11, 12, 13, 9);
    }

    @Test
    void theLearningStatesAreReadAsTheEngineReceivedThem() throws Exception {
        BaselineEvidence.EngineHours read = BaselineEvidence.of(userPrompt("a3s-challenge"), "run-1", 1, null);

        assertThat(read.personalBaselineStatus()).as("the personal baseline line").isEqualTo("ESTABLISHED");
        assertThat(read.workProfileState()).as("the work profile line").isEqualTo("PROVISIONAL");
        assertThat(read.roleScopeState()).as("the role scope line").isEqualTo("PROVISIONAL");
        assertThat(read.observedScopeSummary()).isEqualTo("Observed work-pattern history is limited.");
    }

    /**
     * A v20 prompt names the lines differently (화면재편 F-3, P-3): the personal baseline as "BaselineStatus", the role
     * scope's evidence at the end of its "RoleScope" line, and both hour lists in one "UsualHours" line (the usual
     * hours as ranges, then every hour seen). The prompt is a real decision of run-494441907aba (2026-10-18).
     */
    @Test
    void aV20PromptIsReadWithItsOwnLineNames() throws Exception {
        String prompt = resource("/live/v20-a3-user-prompt.txt");
        BaselineEvidence.EngineHours read = BaselineEvidence.of(prompt, "run-494441907aba", 1, null);

        assertThat(read.personalBaselineStatus()).as("[B1] BaselineStatus: ESTABLISHED (...)").isEqualTo("ESTABLISHED");
        assertThat(read.roleScopeState()).as("RoleScope: ...; evidence PROVISIONAL").isEqualTo("PROVISIONAL");
        assertThat(read.normalAccessHours()).as("the usual hours 10-11, 13-14, 17").containsExactly(10, 11, 13, 14, 17);
        assertThat(read.observedHours()).as("seen 9,10,11,12,13,14,17").containsExactly(9, 10, 11, 12, 13, 14, 17);
        assertThat(read.workProfileState()).as("no such line in v20").isNull();
        assertThat(read.observedScopeSummary()).as("no such line in v20").isNull();
    }

    @Test
    void aV20HourLineWithoutUsualHoursGivesOnlyTheSeenHours() {
        String prompt = "UsualHours: seen 9,10\n";

        assertThat(BaselineEvidence.normalAccessHours(prompt)).isEmpty();
        assertThat(BaselineEvidence.observedHours(prompt)).containsExactly(9, 10);
        assertThat(BaselineEvidence.normalAccessHours("UsualHours: 09-11, 14\n")).containsExactly(9, 10, 11, 14);
    }

    @Test
    void aMissingLineGivesNoHours() {
        assertThat(BaselineEvidence.observedHours("CurrentAccessHourPresentInObservedHours: false\n")).isEmpty();
        assertThat(BaselineEvidence.normalAccessHours(null)).isEmpty();
        assertThat(BaselineEvidence.of("NormalAccessHours: [9]\n", "run-1", 1, null).roleScopeState()).isNull();
    }

    private static String resource(String path) throws Exception {
        try (InputStream in = BaselineEvidenceTest.class.getResourceAsStream(path)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String userPrompt(String name) throws Exception {
        try (InputStream in = BaselineEvidenceTest.class.getResourceAsStream("/anatomy/" + name + ".json")) {
            JsonNode record = JSON.readTree(in);
            return record.path("exchanges").get(0).path("userPrompt").asText();
        }
    }
}
