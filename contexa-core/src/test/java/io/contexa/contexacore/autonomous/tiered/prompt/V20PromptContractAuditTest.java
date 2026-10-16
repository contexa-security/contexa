package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W4-8 (S-28, plan 9): the v19 label contract is not read on a v20 render. A golden v20 render has no v19 contract
 * violation and no v19 label matrix, and its request snapshot is the structured current request it was drawn from.
 */
class V20PromptContractAuditTest {

    @Test
    void aV20RenderIsNotHeldToTheV19LabelContract() {
        SecurityDecisionGoldenRender golden = SecurityDecisionGoldenRender.load();
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.descriptor().promptVersion());
        int withAnHour = 0;
        for (JsonNode goldenCase : golden.cases()) {
            SecurityDecisionGoldenRender.RenderedCase rendered =
                    golden.render(goldenCase, PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT, properties);
            Map<String, Object> metadata = rendered.executionMetadata().supplementalMetadata();

            assertThat((List<?>) metadata.get("promptContractViolations")).as(rendered.caseKey()).isEmpty();
            assertThat((Map<?, ?>) metadata.get("renderedLabelMatrix")).as(rendered.caseKey()).isEmpty();
            if (((Map<?, ?>) metadata.get("renderedRequestSnapshot")).get("currentAccessHour") != null) {
                withAnHour++;
            }
        }
        assertThat(withAnHour).isPositive();
    }
}
