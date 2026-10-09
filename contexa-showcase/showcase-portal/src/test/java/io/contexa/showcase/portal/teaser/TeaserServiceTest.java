package io.contexa.showcase.portal.teaser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import org.junit.jupiter.api.Test;

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

    @Test
    void aDifferenceOutsideTheFactsIsReported() throws Exception {
        JsonNode left = JSON.readTree("{\"facts\":[{\"kind\":\"APPROVAL\"}],\"timeSlot\":\"NIGHT\"}");
        JsonNode right = JSON.readTree("{\"facts\":[],\"timeSlot\":\"AFTERNOON\"}");
        List<String> paths = new ArrayList<>();

        TeaserService.differences("", left, right, paths);

        assertThat(paths).containsExactly("facts", "timeSlot");
    }
}
