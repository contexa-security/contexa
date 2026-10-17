package io.contexa.showcase.portal.teaser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.anatomy.AnatomyBuilder;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy;
import io.contexa.showcase.portal.hook.HookStore;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The teaser "what changed is one approval" rests on the two packaged cases differing in their company facts only
 * (work 19 of docs/showcase/화면설계서-v2-구현계획.md).
 */
class TeaserServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    @Test
    void theAttackerAndTheRealEmployeeCasesDifferOnlyInTheirCompanyFacts() throws Exception {
        ScenarioCatalog catalog = new ScenarioCatalog(JSON);
        ObjectNode attacker = TeaserService.conditions(JSON.valueToTree(catalog.find("A3").orElseThrow()));
        ObjectNode owner = TeaserService.conditions(JSON.valueToTree(catalog.find("A3T").orElseThrow()));
        List<String> paths = new ArrayList<>();

        TeaserService.differences("", attacker, owner, paths);

        assertThat(paths).as("the answers per approach (steps[].expected) are not conditions").containsExactly("facts");
    }

    @Test
    void onlyCardsWhoseSentenceTheRecordMakesFalseAreListedForTheOperator() {
        TeaserService.Source source = new TeaserService.Source("RUN", "run-1");
        TeaserService.View view = new TeaserService.View(Instant.parse("2026-10-08T00:00:00Z"), List.of(
                new TeaserService.Teaser("E1_RESULT_FACTS", Map.of(), true, source, null),
                new TeaserService.Teaser("E1_AFTER_RULES", Map.of(), false, source, null),
                new TeaserService.Teaser("HOOK_TRY", Map.of(), null, source, null),
                new TeaserService.Teaser("G_WHERE_C2", Map.of(), false, source, null)));

        assertThat(view.falseConditions()).as("a card without a fact (null) is never listed")
                .containsExactly("E1_AFTER_RULES", "G_WHERE_C2");
    }

    /**
     * N-DEP-1 (W7-12 C-2): the value screen's "{departures} differences" of the replayed attack are the differences the
     * engine sealed for it: step 1 of run-3766bd77c869 (anatomy/v20-deviations.json) states time, target, class and
     * size as unexplained, next to a CRITICAL resource and a missing approval.
     */
    @Test
    void theResultFactsCountTheDifferencesTheEngineSealedForTheAttack() throws Exception {
        JsonNode attack;
        try (InputStream in = TeaserServiceTest.class.getResourceAsStream("/anatomy/v20-deviations.json")) {
            attack = JSON.readTree(in).path("decisions").get(0);
        }
        DecisionAnatomy anatomy = new AnatomyBuilder(JSON).build("run-3766bd77c869", 1, "EXPORT_STREAM",
                new AnatomyBuilder.StoredDecision(attack.path("requestId").asText(), "ESCALATE", "ESCALATE", null,
                        null, null, null, false, null, null, null, null, null, attack.path("records"),
                        JSON.createArrayNode()),
                List.of(), null, new AnatomyBuilder.Surroundings(null, null, null, Map.of(), Map.of(), null, null,
                        attack.path("userPrompt").asText()));
        HookStore.RunFacts run = new HookStore.RunFacts("run-3766bd77c869", "A3", "COMPLETED", null, null, null, null);

        TeaserService.Teaser teaser = TeaserService.resultFacts(run, anatomy);

        assertThat(attack.path("case").asText()).isEqualTo("A3");
        assertThat(teaser.values()).containsEntry("departures", 4).containsEntry("count", 3)
                .containsEntry("facts", List.of("BASELINE_DEPARTURE", "HIGH_SENSITIVITY", "APPROVAL_MISSING"))
                .containsEntry("sensitivity", "CRITICAL");
        assertThat(teaser.holds()).isTrue();
    }

    @Test
    void aDifferenceOutsideTheFactsIsReported() throws Exception {
        JsonNode left = JSON.readTree("{\"facts\":[{\"kind\":\"APPROVAL\"}],\"timeSlot\":\"NIGHT\"}");
        JsonNode right = JSON.readTree("{\"facts\":[],\"timeSlot\":\"AFTERNOON\"}");
        List<String> paths = new ArrayList<>();

        TeaserService.differences("", left, right, paths);

        assertThat(paths).containsExactly("facts", "timeSlot");
    }
}
