package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent Agent중심-화면 AS-13, AC-7b: a visitor may send a burst of requests at once, live, only up to ten: the case's
 * parallel workers are set to that many in a copy, and a number above ten, below one, or on any other case is refused.
 * The case itself, which the stored measurements ran with sixty, and every other run stay as they were.
 */
class BurstChoiceTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    private final AgentTaskCatalog catalog = newCatalog();

    private static AgentTaskCatalog newCatalog() {
        try {
            return new AgentTaskCatalog(JSON);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private ScenarioDefinition burst() {
        return catalog.find(BurstChoice.BURST_CASE).orElseThrow();
    }

    private static int copiesOf(ScenarioDefinition scenario) {
        return scenario.task().parallel().get(0).copies();
    }

    @Test
    void theLiveLimitIsTenAndTheStoredMeasurementIsSixty() {
        assertThat(BurstChoice.LIVE_MOST).isEqualTo(10);
        assertThat(copiesOf(burst())).as("the case as the stored measurement ran it").isEqualTo(60);
    }

    @Test
    void aNumberUpToTenSetsTheWorkersOfACopy() {
        for (int copies : new int[]{1, 5, 10}) {
            assertThat(copiesOf(BurstChoice.apply(burst(), copies))).isEqualTo(copies);
        }
        ScenarioDefinition ten = BurstChoice.apply(burst(), 10);
        assertThat(ten.task().parallel()).hasSameSizeAs(burst().task().parallel());
        assertThat(ten.task().parallel().get(0).requests()).isEqualTo(burst().task().parallel().get(0).requests());
        assertThat(ten.task().parallel().get(0).startAfterToolCalls())
                .isEqualTo(burst().task().parallel().get(0).startAfterToolCalls());
    }

    @Test
    void aNumberAboveTenOrBelowOneIsRefused() {
        for (int copies : new int[]{11, 30, 60, 1000, 0, -1}) {
            assertThatThrownBy(() -> BurstChoice.apply(burst(), copies)).as("copies " + copies)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void noNumberGivesTheCaseItselfAndOnlyTheBurstCaseTakesANumber() {
        assertThat(BurstChoice.apply(burst(), null)).isSameAs(burst());
        for (String key : new String[]{"T5", "N1", "ED1", "M14A"}) {
            ScenarioDefinition other = catalog.find(key).orElseThrow();
            assertThatThrownBy(() -> BurstChoice.apply(other, 5)).as(key).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(key);
            assertThat(BurstChoice.apply(other, null)).isSameAs(other);
        }
    }

    @Test
    void aCopyChangesOnlyItselfAndHasItsOwnHash() {
        ScenarioDefinition original = burst();
        String before = RunOrchestrator.definitionSha256(JSON, original);

        ScenarioDefinition five = BurstChoice.apply(original, 5);
        ScenarioDefinition ten = BurstChoice.apply(original, 10);

        assertThat(copiesOf(original)).isEqualTo(60);
        assertThat(RunOrchestrator.definitionSha256(JSON, original)).isEqualTo(before);
        assertThat(RunOrchestrator.definitionSha256(JSON, five)).isNotEqualTo(before)
                .isNotEqualTo(RunOrchestrator.definitionSha256(JSON, ten))
                .isEqualTo(RunOrchestrator.definitionSha256(JSON, BurstChoice.apply(original, 5)));
        assertThat(copiesOf(catalog.find(BurstChoice.BURST_CASE).orElseThrow())).isEqualTo(60);
    }

    @Test
    void aBurstCaseIsToldFromOtherAgentCasesByItsParallelWorkers() {
        assertThat(BurstChoice.isBurst(burst())).isTrue();
        assertThat(BurstChoice.isBurst(catalog.find("T5").orElseThrow())).isFalse();
        assertThat(BurstChoice.isBurst(catalog.find("ED1").orElseThrow())).isFalse();
    }
}
