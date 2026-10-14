package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.runtime.OfficialVerificationProbeHeaders;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R4-C9: the renderer injects no fault. Even a fault scenario this JVM authorized (the server-issued capability the
 * verification bridge used to set) leaves the rendered prompt and its metadata as they are without it. The test asks
 * the probe headers for the authorization only while that class stays for the enterprise (R6).
 */
class PromptFaultInjectionRemovedTest {

    private static final SecurityDecisionGoldenRender GOLDEN = SecurityDecisionGoldenRender.load();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void anAuthorizedFaultScenarioLeavesTheRenderedPromptAsItIs() {
        JsonNode goldenCase = GOLDEN.cases().get(0);
        for (String scenario : new String[]{"CCSR_RESOURCE_ACTION_NA", "ALL_12_RUNTIME_SLOT_FAULTS"}) {
            ObjectNode faulted = goldenCase.deepCopy();
            Map<String, Object> authorization = new HashMap<>();
            OfficialVerificationProbeHeaders.authorizeFaultMetadata(authorization, scenario);
            ObjectNode facts = (ObjectNode) faulted.path("requestFacts");
            authorization.forEach((key, value) -> facts.set(key, JSON.valueToTree(value)));

            SecurityDecisionGoldenRender.RenderedCase plain =
                    GOLDEN.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);
            SecurityDecisionGoldenRender.RenderedCase withScenario =
                    GOLDEN.render(faulted, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT);

            assertThat(withScenario.userText()).as(scenario).isEqualTo(plain.userText());
            assertThat(withScenario.executionMetadata().toMetadataMap()).as(scenario)
                    .doesNotContainKeys("pqaPromptFaultApplied", "pqaPromptFaultScenario", "pqaPromptFaultTarget");
        }
    }
}
