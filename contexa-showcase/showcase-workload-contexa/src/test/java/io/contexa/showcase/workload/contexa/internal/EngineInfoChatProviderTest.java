package io.contexa.showcase.workload.contexa.internal;

import io.contexa.autoconfigure.iam.admin.PqaOssSealedEvidenceCaptureProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.info.BuildProperties;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Model comparison: control D states the chat model of the provider it runs, so a template and a measurement are
 * recorded under the model that really decided. An Anthropic engine sends no OpenAI reasoning effort or verbosity, so
 * its model settings state only the output limit it sends.
 */
class EngineInfoChatProviderTest {

    @Test
    void anOpenAiEngineStatesItsOpenAiModelAndSettings() {
        Map<String, Object> engine = engine("openai", "gpt-6-luna", "claude-haiku-5-5");

        assertThat(engine).containsEntry("chatProvider", "openai").containsEntry("chatModel", "gpt-6-luna");
        // The defaults since W4-6 (G-5): a reasoning model's reasoning tokens count against the output limit.
        assertThat(engine.get("layer1Model")).isEqualTo(settings("gpt-6-luna", "low", "low", 2048));
    }

    /** 판정층 E-8c: each layer states the model the core selects for it, set in application.yml. */
    @Test
    void eachLayerStatesTheModelItsAnalysisRunsOn() {
        TieredLLMProperties layers = new TieredLLMProperties();
        layers.getLayer1().setModel("gpt-6-luna");
        layers.getLayer2().setModel("gpt-6.1-sol");

        Map<String, Object> engine = engine("openai", "gpt-6-luna", "", layers);

        assertThat(engine.get("layer1Model")).isEqualTo(settings("gpt-6-luna", "low", "low", 2048));
        assertThat(engine.get("layer2Model")).isEqualTo(settings("gpt-6.1-sol", "low", "low", 2560));
    }

    @Test
    void anAnthropicEngineStatesItsAnthropicModelAndOnlyTheSettingsItSends() {
        Map<String, Object> engine = engine("anthropic", "", "claude-haiku-5-5");

        assertThat(engine).containsEntry("chatProvider", "anthropic").containsEntry("chatModel", "claude-haiku-5-5");
        assertThat(engine.get("layer1Model")).isEqualTo(settings("claude-haiku-5-5", null, null, 2048));
        assertThat(engine.get("layer2Model")).isEqualTo(settings("claude-haiku-5-5", null, null, 2560));
    }

    /** A layer's settings; without a layer model the layer runs on the primary chat model, which it states. */
    private static Map<String, Object> settings(String model, String effort, String verbosity, int maxOutputTokens) {
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("model", model);
        settings.put("reasoningEffort", effort);
        settings.put("verbosity", verbosity);
        settings.put("maxOutputTokens", maxOutputTokens);
        return settings;
    }

    private static Map<String, Object> engine(String provider, String openAiModel, String anthropicModel) {
        return engine(provider, openAiModel, anthropicModel, null);
    }

    private static Map<String, Object> engine(String provider, String openAiModel, String anthropicModel,
                                              TieredLLMProperties layers) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("tiered", new TieredStrategyProperties());
        if (layers != null) {
            beans.addBean("layers", layers);
        }
        ContexaInternalController controller = new ContexaInternalController(null, null, null, null, null, null,
                null, null, null, null, beans.getBeanProvider(TieredStrategyProperties.class),
                new SecurityZeroTrustProperties(), provider, openAiModel, anthropicModel, "text-embedding-3-small", 1024,
                beans.getBeanProvider(BuildProperties.class), false, null,
                beans.getBeanProvider(PqaOssSealedEvidenceCaptureProperties.class),
                beans.getBeanProvider(TieredLLMProperties.class));
        return controller.engine();
    }
}
