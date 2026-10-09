package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

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

    @Test
    void aMissingLineGivesNoHours() {
        assertThat(BaselineEvidence.observedHours("CurrentAccessHourPresentInObservedHours: false\n")).isEmpty();
        assertThat(BaselineEvidence.normalAccessHours(null)).isEmpty();
        assertThat(BaselineEvidence.of("NormalAccessHours: [9]\n", "run-1", 1, null).roleScopeState()).isNull();
    }

    private static String userPrompt(String name) throws Exception {
        try (InputStream in = BaselineEvidenceTest.class.getResourceAsStream("/anatomy/" + name + ".json")) {
            JsonNode record = JSON.readTree(in);
            return record.path("exchanges").get(0).path("userPrompt").asText();
        }
    }
}
