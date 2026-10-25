package io.contexa.showcase.workload.contexa.model;

import io.micrometer.observation.ObservationRegistry;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.retry.RetryUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClient;

/**
 * Control D's Layer 2 on Anthropic while Layer 1 stays on OpenAI (user decision 2026-10-25, docs/agent
 * 위임결정기록 DD-38). The engine already runs the layers on different providers: a model id with a chat runtime
 * binding ({@code contexa.llm.bindings.chat}) is resolved to that binding's chat model, so this only provides the
 * Anthropic chat model the binding in application.yml names. It is built the way Spring AI's own Anthropic
 * auto-configuration builds it (which is off while the primary chat provider is OpenAI), on the application's
 * {@link RestClient.Builder}, so the provider HTTP capture and the usage meter see its calls like Layer 1's.
 */
@Configuration(proxyBeanMethods = false)
public class Layer2AnthropicConfiguration {

    private static final Logger log = LoggerFactory.getLogger(Layer2AnthropicConfiguration.class);

    /** The bean the chat binding of the Layer 2 model names in application.yml. */
    public static final String BEAN = "layer2AnthropicChatModel";

    /** Anthropic requires a limit on the answer; the engine sets the layer's own limit on each call. */
    private static final int DEFAULT_MAX_TOKENS = 2560;

    /** The key placeholder that lets the context load when no key is set; the start check then refuses with the reason. */
    private static final String NO_KEY = "no-anthropic-key";

    @Bean(BEAN)
    public AnthropicChatModel layer2AnthropicChatModel(
            @Value("${spring.ai.anthropic.api-key:}") String apiKey,
            @Value("${spring.ai.anthropic.base-url:}") String baseUrl,
            @Value("${showcase.layer2.anthropic.model:claude-sonnet-5-5}") String model,
            @Value("${contexa.security.tiered.layer2.max-output-tokens:" + DEFAULT_MAX_TOKENS + "}") int maxTokens,
            ObjectProvider<RestClient.Builder> restClientBuilder,
            ObjectProvider<ResponseErrorHandler> responseErrorHandler,
            ObjectProvider<RetryTemplate> retryTemplate,
            ObjectProvider<ToolCallingManager> toolCallingManager,
            ObjectProvider<ObservationRegistry> observationRegistry) {
        AnthropicApi.Builder api = AnthropicApi.builder()
                .apiKey(apiKey == null || apiKey.isBlank() ? NO_KEY : apiKey.trim())
                .restClientBuilder(restClientBuilder.getIfAvailable(RestClient::builder))
                .responseErrorHandler(responseErrorHandler.getIfAvailable(() -> RetryUtils.DEFAULT_RESPONSE_ERROR_HANDLER));
        if (baseUrl != null && !baseUrl.isBlank()) {
            api.baseUrl(baseUrl.trim());
        }
        return AnthropicChatModel.builder()
                .anthropicApi(api.build())
                .defaultOptions(AnthropicChatOptions.builder().model(model).maxTokens(maxTokens).build())
                .toolCallingManager(toolCallingManager.getIfAvailable(() -> ToolCallingManager.builder().build()))
                .retryTemplate(retryTemplate.getIfAvailable(() -> RetryUtils.DEFAULT_RETRY_TEMPLATE))
                .observationRegistry(observationRegistry.getIfUnique(() -> ObservationRegistry.NOOP))
                .build();
    }

    /**
     * Stops the start when Layer 2 runs on the Anthropic model and the key is missing, refused, or has no access to the
     * model. Anything else (the API not reachable, an unexpected status) is logged and the start goes on: the first
     * call then tells.
     */
    @Bean
    @ConditionalOnProperty(name = "showcase.layer2.anthropic.verify-key", havingValue = "true", matchIfMissing = true)
    public SmartInitializingSingleton layer2AnthropicAvailability(
            @Value("${contexa.security.tiered.llm.layer2.model:}") String layer2Model,
            @Value("${showcase.layer2.anthropic.model:claude-sonnet-5-5}") String anthropicModel,
            @Value("${spring.ai.anthropic.api-key:}") String apiKey,
            @Value("${spring.ai.anthropic.base-url:}") String baseUrl) {
        return () -> verify(layer2Model, anthropicModel, apiKey, baseUrl);
    }

    static void verify(String layer2Model, String anthropicModel, String apiKey, String baseUrl) {
        if (layer2Model == null || !layer2Model.trim().equalsIgnoreCase(anthropicModel.trim())) {
            return;
        }
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("Layer 2 runs on " + anthropicModel + " but no Anthropic key is set. Set the "
                    + "environment variable ANTHROPIC_API_KEY (or SHOWCASE_ANTHROPIC_API_KEY) to a valid key.");
        }
        AnthropicAvailability.Result result = AnthropicAvailability.check(baseUrl, apiKey.trim(), anthropicModel.trim());
        switch (result.outcome()) {
            case ACCEPTED -> {
            }
            case REFUSED_KEY -> throw new IllegalStateException("Layer 2 runs on " + anthropicModel + " but Anthropic "
                    + "refused the key (HTTP " + result.status() + "). Set the environment variable ANTHROPIC_API_KEY "
                    + "(or SHOWCASE_ANTHROPIC_API_KEY) to a valid key.");
            case NO_MODEL -> throw new IllegalStateException("Layer 2 runs on " + anthropicModel + " but the Anthropic "
                    + "key has no model of that name (HTTP 404).");
            default -> log.error("Anthropic availability of {} could not be read ({}); the start goes on and the first "
                    + "Layer 2 call tells.", anthropicModel, result.detail());
        }
    }
}
