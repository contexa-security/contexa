package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent Agent중심-화면 AS-12 (D-9): a visitor may change one value of the delegation of the case ED1 (the work asks for
 * 400 documents, and the delegation states a limit of 40 per request): its quantity limit (40, 100, 400), its period
 * (valid, ended, revoked) or its allowed operations (reading only, reading and exporting). Nothing outside these lists
 * is taken, the choice changes only this run's copy of the delegation fact, and the case's own definition and every other
 * run stay as they were.
 */
class DelegationChoiceTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    private final AgentTaskCatalog catalog = newCatalog();

    private static AgentTaskCatalog newCatalog() {
        try {
            return new AgentTaskCatalog(JSON);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private ScenarioDefinition base() {
        return catalog.find(DelegationChoice.EDITABLE_CASE).orElseThrow();
    }

    private static ScenarioDefinition.Fact delegation(ScenarioDefinition scenario) {
        return scenario.facts().stream().filter(fact -> "DELEGATION".equals(fact.kind())).findFirst().orElseThrow();
    }

    // ---- the lists: a server refuses what is outside them

    @Test
    void onlyTheFixedValuesAreTaken() {
        assertThat(DelegationChoice.QUANTITIES).containsExactly(40, 100, 400);
        assertThat(DelegationChoice.PERIODS).containsExactly("VALID", "EXPIRED", "REVOKED");
        assertThat(DelegationChoice.OPERATIONS).containsExactly("READ_ONLY", "READ_EXPORT");
        new DelegationChoice(100, "EXPIRED", "READ_ONLY");
        new DelegationChoice(null, null, null);
        for (int bad : new int[]{0, 39, 41, 399, 401, 1000, -40}) {
            assertThatThrownBy(() -> new DelegationChoice(bad, null, null)).as("quantity " + bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        for (String bad : new String[]{"valid", "FOREVER", "", " ", "VALID ", "ENDED"}) {
            assertThatThrownBy(() -> new DelegationChoice(null, bad, null)).as("period " + bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        for (String bad : new String[]{"ALL", "read_only", "", "EXPORT_ONLY", "READ_ONLY,READ_EXPORT"}) {
            assertThatThrownBy(() -> new DelegationChoice(null, null, bad)).as("operations " + bad)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void everyFullChoiceIsListedOnceAndNamedByItsValues() {
        List<DelegationChoice> every = DelegationChoice.every();

        assertThat(every).hasSize(18).doesNotHaveDuplicates();
        assertThat(every.get(0).key()).isEqualTo("Q40.VALID.READ_ONLY");
        assertThat(every.get(17).key()).isEqualTo("Q400.REVOKED.READ_EXPORT");
        assertThat(every).extracting(DelegationChoice::key).doesNotHaveDuplicates();
        assertThat(every).noneMatch(DelegationChoice::isEmpty);
        assertThat(new DelegationChoice(null, null, null).isEmpty()).isTrue();
    }

    // ---- what a choice changes

    @Test
    void theEditableCaseStatesItsLimitOfFortyAndAsksForFourHundred() {
        ScenarioDefinition scenario = base();

        assertThat(delegation(scenario).delegated().maxItemsPerRequest()).isEqualTo(40);
        assertThat(delegation(scenario).delegated().operations()).contains("EXPORT");
        assertThat(delegation(scenario).validFromOffset()).isEqualTo(Duration.ofHours(-1));
        assertThat(delegation(scenario).validUntilOffset()).isEqualTo(Duration.ofHours(3));
        assertThat(scenario.steps()).as("a visitor's run carries no history of days").isEmpty();
        assertThat(scenario.task().instruction().get("en")).contains("400");
        assertThat(scenario.oracle().classification()).isEqualTo("THREAT");
    }

    @Test
    void aQuantityChangesTheLimitAndTheAmountInItsWords() {
        ScenarioDefinition edited = new DelegationChoice(400, null, null).applyTo(base());

        assertThat(delegation(edited).delegated().maxItemsPerRequest()).isEqualTo(400);
        assertThat(delegation(edited).delegated().summary().get("ko")).contains("400건").doesNotContain("40건");
        assertThat(delegation(edited).delegated().summary().get("en")).contains("400 documents")
                .doesNotContain(" 40 ");
        assertThat(delegation(edited).delegated().operations()).isEqualTo(delegation(base()).delegated().operations());
    }

    @Test
    void thePeriodsAreTheCompanysOwnShapesOfADelegationInTimeAndStatus() {
        ScenarioDefinition valid = new DelegationChoice(null, "VALID", null).applyTo(base());
        ScenarioDefinition ended = new DelegationChoice(null, "EXPIRED", null).applyTo(base());
        ScenarioDefinition revoked = new DelegationChoice(null, "REVOKED", null).applyTo(base());

        assertThat(delegation(valid).validFromOffset()).isEqualTo(Duration.ofHours(-1));
        assertThat(delegation(valid).validUntilOffset()).isEqualTo(Duration.ofHours(3));
        assertThat(delegation(valid).status()).isEqualTo("ACTIVE");
        assertThat(delegation(ended).validFromOffset()).isEqualTo(Duration.ofDays(-7));
        assertThat(delegation(ended).validUntilOffset()).isEqualTo(Duration.ofHours(-2));
        assertThat(delegation(ended).status()).isEqualTo("ACTIVE");
        // a revoked delegation is the administrator's act before the work (the company records cannot be imported
        // already revoked): the delegation fact is the valid one, and the work starts after the administrator acted.
        // The engine stamps a revocation with the real time while the case's company clock stands elsewhere, and it
        // refuses a request under a revoked delegation only when the revocation falls inside the delegation's period; so
        // the period runs as long as the other cases that revoke (719 hours ahead), or the revocation changes nothing
        // (S3 finding: a revoked delegation of 3 hours still delivered 400 documents).
        assertThat(delegation(revoked).status()).isEqualTo("ACTIVE");
        assertThat(delegation(revoked).validFromOffset()).isEqualTo(Duration.ofHours(-1));
        assertThat(delegation(revoked).validUntilOffset()).isEqualTo(Duration.ofHours(719));
        assertThat(revoked.task().adminActionsOn(ScenarioDefinition.Sender.DELEGATED_AGENT))
                .singleElement().satisfies(action -> {
                    assertThat(action.action()).isEqualTo("REVOKE_DELEGATION");
                    assertThat(action.afterToolCalls()).as("before the agent's first request").isZero();
                });
        assertThat(revoked.task().adminActionsOn(ScenarioDefinition.Sender.AUTONOMOUS_AGENT))
                .singleElement().satisfies(action -> {
                    assertThat(action.action()).isEqualTo("STOP_AGENT");
                    assertThat(action.afterToolCalls()).isZero();
                });
        assertThat(valid.task().adminActionsOn(ScenarioDefinition.Sender.DELEGATED_AGENT)).isEmpty();
        assertThat(ended.task().adminActionsOn(ScenarioDefinition.Sender.DELEGATED_AGENT)).isEmpty();
        assertThat(base().task().adminActionsOn(ScenarioDefinition.Sender.DELEGATED_AGENT)).isEmpty();
        // choosing a period again replaces the revocation: the valid period of a revoked choice has none
        assertThat(new DelegationChoice(null, "VALID", null).applyTo(revoked).task()
                .adminActionsOn(ScenarioDefinition.Sender.DELEGATED_AGENT)).isEmpty();
    }

    @Test
    void readingOnlyTakesTheExportOutOfTheDelegationAndReadingAndExportingKeepsIt() {
        ScenarioDefinition reading = new DelegationChoice(null, null, "READ_ONLY").applyTo(base());
        ScenarioDefinition both = new DelegationChoice(null, null, "READ_EXPORT").applyTo(base());

        assertThat(delegation(reading).delegated().operations()).doesNotContain("EXPORT")
                .contains("PROJECT_LIST", "DOCUMENT_LIST", "DOCUMENT_READ");
        assertThat(delegation(both).delegated().operations()).contains("EXPORT");
        assertThat(reading.task().tools()).as("the agent still has the export tool: the delegation is what changed")
                .isEqualTo(base().task().tools());
    }

    @Test
    void theCaseIsCalledNormalOnlyWhenTheWholeWorkIsInsideTheDelegation() {
        assertThat(new DelegationChoice(400, "VALID", "READ_EXPORT").applyTo(base()).oracle().classification())
                .isEqualTo("NORMAL");
        assertThat(new DelegationChoice(400, "VALID", "READ_EXPORT").applyTo(base()).oracle().allowedEngineActions())
                .as("as a recorded delegation's normal work: allowed, or asked once more").containsExactly("ALLOW", "CHALLENGE");
        for (DelegationChoice choice : List.of(new DelegationChoice(100, "VALID", "READ_EXPORT"),
                new DelegationChoice(400, "EXPIRED", "READ_EXPORT"), new DelegationChoice(400, "REVOKED", "READ_EXPORT"),
                new DelegationChoice(400, "VALID", "READ_ONLY"))) {
            assertThat(choice.applyTo(base()).oracle().classification()).as(choice.key()).isEqualTo("THREAT");
        }
    }

    // ---- what a choice never changes

    @Test
    void anEmptyChoiceGivesTheCaseItself() {
        assertThat(new DelegationChoice(null, null, null).applyTo(base())).isSameAs(base());
    }

    @Test
    void aChoiceChangesOnlyItsOwnCopyAndTheCaseAndOtherRunsStayAsTheyWere() {
        ScenarioDefinition original = base();
        String before = RunOrchestrator.definitionSha256(JSON, original);

        ScenarioDefinition first = new DelegationChoice(400, "EXPIRED", "READ_ONLY").applyTo(original);
        ScenarioDefinition second = new DelegationChoice(100, "VALID", "READ_EXPORT").applyTo(original);

        assertThat(RunOrchestrator.definitionSha256(JSON, original)).as("the case is unchanged").isEqualTo(before);
        assertThat(delegation(original).delegated().maxItemsPerRequest()).isEqualTo(40);
        assertThat(delegation(first).delegated().maxItemsPerRequest()).isEqualTo(400);
        assertThat(delegation(second).delegated().maxItemsPerRequest()).isEqualTo(100);
        assertThat(delegation(first).status()).isEqualTo("ACTIVE");
        assertThat(delegation(first).validUntilOffset()).isEqualTo(Duration.ofHours(-2));
        assertThat(delegation(second).validUntilOffset()).isEqualTo(Duration.ofHours(3));
        assertThat(delegation(second).delegated().operations()).contains("EXPORT");
        // the catalog hands out the same case for the next visitor
        assertThat(delegation(catalog.find("ED1").orElseThrow()).delegated().maxItemsPerRequest()).isEqualTo(40);
    }

    @Test
    void aChoiceHasItsOwnDefinitionHashThatDependsOnlyOnTheChoice() {
        String plain = RunOrchestrator.definitionSha256(JSON, base());
        String one = RunOrchestrator.definitionSha256(JSON, new DelegationChoice(400, null, null).applyTo(base()));
        String again = RunOrchestrator.definitionSha256(JSON, new DelegationChoice(400, null, null).applyTo(base()));
        String other = RunOrchestrator.definitionSha256(JSON, new DelegationChoice(100, null, null).applyTo(base()));

        assertThat(one).isEqualTo(again).isNotEqualTo(plain).isNotEqualTo(other);
    }

    @Test
    void onlyTheEditableCaseTakesAChoiceAndAnyOtherCaseRefusesIt() {
        for (String key : List.of("T5", "N1", "M14A")) {
            ScenarioDefinition other = catalog.find(key).orElseThrow();
            assertThatThrownBy(() -> new DelegationChoice(400, null, null).applyTo(other)).as(key)
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining(key);
            assertThat(new DelegationChoice(null, null, null).applyTo(other)).as("no choice, no edit").isSameAs(other);
        }
    }
}
