package io.contexa.showcase.workload.contexa.internal;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.info.BuildProperties;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * LU-6 (P3 extra 46): control D states the prompt bundle it runs, so the portal can tell measurements of different
 * bundles apart. The configuration selector runs the configured bundle, or the build's default bundle when the build
 * cannot run it; with the registry selector the bundle is chosen per request and is not stated.
 */
class EngineInfoPromptBundleTest {

    @Test
    void theEngineStatesThePromptBundleTheConfigurationRuns() {
        String v20 = SecurityDecisionPromptBundles.V20.version();

        assertThat(engine(v20, TieredStrategyProperties.PromptBundle.Selector.CONFIGURATION))
                .containsEntry("promptBundle", v20);
        assertThat(engine(null, TieredStrategyProperties.PromptBundle.Selector.CONFIGURATION))
                .containsEntry("promptBundle", SecurityDecisionPromptBundles.DEFAULT.version());
        assertThat(engine("2000.01.01-v1.0", TieredStrategyProperties.PromptBundle.Selector.CONFIGURATION))
                .as("a bundle this build cannot run").containsEntry("promptBundle",
                        SecurityDecisionPromptBundles.DEFAULT.version());
        assertThat(engine(v20, TieredStrategyProperties.PromptBundle.Selector.REGISTRY))
                .doesNotContainKey("promptBundle");
    }

    private static Map<String, Object> engine(String active, TieredStrategyProperties.PromptBundle.Selector selector) {
        TieredStrategyProperties tiered = new TieredStrategyProperties();
        tiered.getPromptBundle().setActive(active);
        tiered.getPromptBundle().setSelector(selector);
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("tiered", tiered);
        ContexaInternalController controller = new ContexaInternalController(null, null, null, null, null, null,
                null, null, null, null, beans.getBeanProvider(TieredStrategyProperties.class),
                new SecurityZeroTrustProperties(), "openai", "gpt-6-luna", "", "text-embedding-3-small", 1024,
                beans.getBeanProvider(BuildProperties.class), false, null);
        return controller.engine();
    }
}
