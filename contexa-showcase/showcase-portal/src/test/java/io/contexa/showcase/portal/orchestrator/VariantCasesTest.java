package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.context.CompanyRecordsExport;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A6-4: the variants of the checking cases ({@code agent-tasks/V<case>C|E.json}): for each category one
 * variant of the condition (C) and one of the wording (E), measured beside the original case.
 */
class VariantCasesTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    private Map<String, ScenarioDefinition> load(String pattern) throws IOException {
        Map<String, ScenarioDefinition> cases = new LinkedHashMap<>();
        for (Resource resource : new PathMatchingResourcePatternResolver().getResources(
                "classpath:/agent-tasks/" + pattern)) {
            try (InputStream stream = resource.getInputStream()) {
                ScenarioDefinition scenario = json.readValue(stream, ScenarioDefinition.class);
                assertThat(resource.getFilename()).isEqualTo(scenario.key() + ".json");
                cases.put(scenario.key(), scenario);
            }
        }
        return cases;
    }

    @Test
    void everyCategoryHasAConditionVariantAndAWordingVariantOfItsCase() throws IOException {
        Map<String, ScenarioDefinition> variants = load("V*.json");
        Map<String, ScenarioDefinition> bases = new LinkedHashMap<>();
        bases.putAll(load("N*.json"));
        bases.putAll(load("T*.json"));

        assertThat(variants).containsOnlyKeys("VN1C", "VN1E", "VT1C", "VT1E", "VT2C", "VT2E", "VT4C", "VT4E", "VT5C",
                "VT5E");
        for (ScenarioDefinition variant : variants.values()) {
            String key = variant.key();
            ScenarioDefinition base = bases.get(key.substring(1, 3));
            assertThat(base).as(key + " has its case").isNotNull();
            // The same category: the same kind of case, agent, person, delegation structure and tools.
            assertThat(variant.oracle().classification()).as(key).isEqualTo(base.oracle().classification());
            assertThat(variant.protagonist()).as(key).isEqualTo(base.protagonist());
            assertThat(variant.agent()).as(key).isEqualTo(base.agent());
            assertThat(variant.task().sender()).as(key).isEqualTo(base.task().sender());
            assertThat(variant.task().tools()).as(key).isEqualTo(base.task().tools());
            assertThat(variant.task().paths()).as("the delegated path, like the case itself").isNull();
            assertThat(variant.title()).as(key).containsOnlyKeys("ko", "en").isNotEqualTo(base.title());
            assertThat(variant.task().instruction()).as(key).containsOnlyKeys("ko", "en");
            assertThat(variant.oracle().rationale()).as(key).containsOnlyKeys("ko", "en");
            assertThat(within(variant.agent().network(), CompanyRecordsExport.AGENT_PLATFORM_NETWORK)).as(key).isTrue();
            if (variant.oracle().classification().equals("NORMAL")) {
                assertThat(variant.task().proof().deliverable()).as(key).isNotBlank();
                assertThat(variant.task().proof().mustNotLeave()).as(key).isEmpty();
            } else {
                assertThat(variant.task().proof().deliverable()).as(key).isNull();
                assertThat(variant.task().proof().mustNotLeave()).as(key).isNotEmpty();
            }
            // A variant of the wording changes the words and no condition; one of the condition changes a condition.
            if (key.endsWith("E")) {
                assertThat(variant.task().proof().mustNotLeave()).as(key).isEqualTo(base.task().proof().mustNotLeave());
                assertThat(variant.task().proof().workNeeds()).as(key).isEqualTo(base.task().proof().workNeeds());
                assertThat(variant.task().instruction().get("en").equals(base.task().instruction().get("en"))
                        && String.valueOf(variant.task().agentPrompt()).equals(String.valueOf(base.task().agentPrompt()))
                        && variant.facts().equals(base.facts())).as(key + " changes some words").isFalse();
            }
        }
        // The conditions each variant changes.
        assertThat(variants.get("VT1C").task().proof().mustNotLeave()).containsExactly("GB-500");
        assertThat(variants.get("VT4C").task().proof().workNeeds()).isEqualTo(3);
        assertThat(variants.get("VT2C").task().instruction().get("en")).contains("CUS-0003");
        assertThat(variants.get("VN1C").task().instruction().get("en")).contains("specification");
        assertThat(variants.get("VT5C").facts()).isNotEqualTo(bases.get("T5").facts());
        // The wording variant of an injection changes the sentence, keeps its target.
        assertThat(variants.get("VT1E").facts()).isNotEqualTo(bases.get("T1").facts());
        assertThat(variants.get("VT1E").task().proof().mustNotLeave()).containsExactly("CP-330");
    }

    private static boolean within(String network, String block) {
        int prefix = Integer.parseInt(block.substring(block.indexOf('/') + 1));
        if (Integer.parseInt(network.substring(network.indexOf('/') + 1)) < prefix) {
            return false;
        }
        long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (address(network) & mask) == (address(block) & mask);
    }

    private static long address(String cidr) {
        long value = 0;
        for (String part : cidr.substring(0, cidr.indexOf('/')).split("\\.")) {
            value = (value << 8) | Long.parseLong(part);
        }
        return value;
    }
}
