package io.contexa.showcase.portal.combination;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Deck p.13 and docs/showcase/P4-설계.md 1절: the 192 cells, their scenarios and the version key. */
class CombinationTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void theGridHas192DistinctCellsWhoseKeysReadBack() {
        List<Combination> all = CombinationCatalog.all();
        Set<String> keys = new HashSet<>();
        all.forEach(combination -> keys.add(combination.key()));

        assertThat(all).hasSize(192);
        assertThat(keys).hasSize(192);
        Combination cell = Combination.parse("adm-a.DAWN.4831.MATCH.USUAL");
        assertThat(cell).isEqualTo(new Combination("adm-a", TimeSlot.DAWN, 4831, Combination.Ticket.MATCH,
                Combination.Device.USUAL));
        assertThat(cell.key().length()).isLessThanOrEqualTo(48);
        for (String bad : List.of("adm-a.DAWN.4831.MATCH", "x.DAWN.4831.MATCH.USUAL", "adm-a.DAWN.4000.MATCH.USUAL",
                "adm-a.NOON.4831.MATCH.USUAL")) {
            assertThatThrownBy(() -> Combination.parse(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void aCellBecomesAnExportOfGb500WithItsTicketNamedInTheRequest() {
        ScenarioDefinition matched = CombinationCatalog.scenario(Combination.parse("eng-k.EVENING.480.MATCH.NEW"));
        ScenarioDefinition.Step step = matched.steps().get(0);
        assertThat(matched.key()).isEqualTo("eng-k.EVENING.480.MATCH.NEW");
        assertThat(matched.protagonist()).isEqualTo("eng-k");
        assertThat(matched.timeSlot()).isEqualTo(TimeSlot.EVENING);
        assertThat(matched.device()).isEqualTo(ScenarioDefinition.Device.NEW);
        assertThat(step.operation()).isEqualTo(BusinessOperation.EXPORT);
        assertThat(step.project()).isEqualTo("GB-500");
        assertThat(step.items()).isEqualTo(480);
        assertThat(step.claimedTicket()).isEqualTo("{fact:1}");
        assertThat(matched.facts()).singleElement().satisfies(fact -> {
            assertThat(fact.kind()).isEqualTo("TICKET");
            assertThat(fact.project()).isEqualTo("GB-500");
        });
        assertThat(matched.oracle().classification()).isEqualTo("UNCERTAIN");

        ScenarioDefinition mismatched = CombinationCatalog.scenario(Combination.parse("eng-k.EVENING.480.MISMATCH.NEW"));
        assertThat(mismatched.facts().get(0).project()).isEqualTo("CP-330");
        ScenarioDefinition none = CombinationCatalog.scenario(Combination.parse("eng-k.EVENING.480.NONE.USUAL"));
        assertThat(none.facts()).isEmpty();
        assertThat(none.steps().get(0).claimedTicket()).isNull();
        assertThat(none.device()).isEqualTo(ScenarioDefinition.Device.USUAL);
    }

    @Test
    void theVersionKeyChangesWithTheTemplateTheRulesOrTheModelAndNothingElse() throws Exception {
        JsonNode engine = json.readTree("""
                {"codeCommit": "c", "engineVersion": "0.1.0", "effectiveMode": "ENFORCE", "chatModel": "gpt-5-nano",
                 "embeddingModel": "text-embedding-3-small", "embeddingDimensions": 1024, "timeZone": "UTC",
                 "endpointProtection": {"POST /api/projects/*/exports": "sync", "GET /api/projects": "none"},
                 "forcedActions": false}""");
        JsonNode reordered = json.readTree("""
                {"forcedActions": false, "timeZone": "UTC", "embeddingDimensions": 1024,
                 "endpointProtection": {"GET /api/projects": "none", "POST /api/projects/*/exports": "sync"},
                 "embeddingModel": "text-embedding-3-small", "chatModel": "gpt-5-nano", "effectiveMode": "ENFORCE",
                 "engineVersion": "0.1.0", "codeCommit": "c"}""");
        JsonNode rules = json.readTree("{\"sha256\": \"r1\"}");
        String key = CombinationVersions.key(engine, rules, "tpl-1", "k1");

        assertThat(key).hasSize(64).isEqualTo(CombinationVersions.key(reordered, rules, "tpl-1", "k1"));
        assertThat(CombinationVersions.key(engine, rules, "tpl-2", "k1")).isNotEqualTo(key);
        assertThat(CombinationVersions.key(engine, json.readTree("{\"sha256\": \"r2\"}"), "tpl-1", "k1"))
                .isNotEqualTo(key);
        JsonNode otherModel = ((ObjectNode) engine.deepCopy())
                .put("chatModel", "gpt-5-mini");
        assertThat(CombinationVersions.key(otherModel, rules, "tpl-1", "k1")).isNotEqualTo(key);
    }
}
