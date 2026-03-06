package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Anthropic Claude model provider.
 * Extends BaseModelProvider to reuse common logic.
 * Creates models dynamically based on model ID.
 */
@Slf4j
public class AnthropicModelProvider extends BaseModelProvider {

    @Value("${spring.ai.anthropic.api-key:}")
    private String apiKey;

    @Value("${spring.ai.anthropic.base-url:https://api.anthropic.com}")
    private String anthropicBaseUrl;

    @Value("${spring.ai.anthropic.enabled:true}")
    private boolean anthropicEnabled;

    @Autowired(required = false)
    private AnthropicApi anthropicApi;

    // ========== Abstract Method Implementation ==========

    @Override
    public String getProviderName() {
        return "anthropic";
    }

    @Override
    public String getDescription() {
        return "Anthropic Claude model provider for advanced AI capabilities";
    }

    @Override
    protected String getProviderBaseUrl() {
        return anthropicBaseUrl;
    }

    @Override
    protected boolean isProviderEnabled() {
        return anthropicEnabled && apiKey != null && !apiKey.isEmpty();
    }

    @Override
    protected void doInitialize(Map<String, Object> config) {
        if (apiKey == null || apiKey.isEmpty()) {
            log.error("Anthropic API key is not set, but continuing");
        }
    }

    @Override
    public boolean isReady() {
        return ready && apiKey != null && !apiKey.isEmpty();
    }

    @Override
    public int getPriority() {
        return 20;
    }

    @Override
    public ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config) {
        String modelId = descriptor.getModelId();

        if (hasCachedModel(modelId)) {
            return getCachedModel(modelId);
        }

        try {
            AnthropicChatOptions.Builder optionsBuilder = AnthropicChatOptions.builder()
                    .model(modelId);

            if (descriptor.getOptions() != null) {
                ModelDescriptor.ModelOptions options = descriptor.getOptions();
                if (options.getTemperature() != null) {
                    optionsBuilder.temperature(options.getTemperature());
                }
                if (options.getTopP() != null) {
                    optionsBuilder.topP(options.getTopP());
                }
                if (options.getTopK() != null) {
                    optionsBuilder.topK(options.getTopK());
                }
            }

            if (descriptor.getCapabilities() != null) {
                optionsBuilder.maxTokens(descriptor.getCapabilities().getMaxOutputTokens());
            }

            if (config != null) {
                if (config.containsKey("temperature")) {
                    optionsBuilder.temperature((Double) config.get("temperature"));
                }
                if (config.containsKey("maxTokens")) {
                    optionsBuilder.maxTokens((Integer) config.get("maxTokens"));
                }
                if (config.containsKey("stopSequences")) {
                    @SuppressWarnings("unchecked")
                    List<String> stopSequences = (List<String>) config.get("stopSequences");
                    optionsBuilder.stopSequences(stopSequences);
                }
            }

            AnthropicChatOptions anthropicOptions = optionsBuilder.build();

            if (!isReady()) {
                throw new ModelSelectionException("Anthropic API not configured. Please set ANTHROPIC_API_KEY",
                        modelId);
            }

            AnthropicChatModel chatModel = AnthropicChatModel.builder()
                    .anthropicApi(getAnthropicApi())
                    .defaultOptions(anthropicOptions)
                    .build();

            cacheModel(modelId, chatModel);

            return chatModel;

        } catch (Exception e) {
            log.error("Failed to create Anthropic model: {}", modelId, e);
            throw new RuntimeException("Failed to create Anthropic model: " + modelId, e);
        }
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        try {
            if (apiKey == null || apiKey.isEmpty()) {
                return HealthStatus.unhealthy("API key not configured");
            }

            if (baseUrl == null) {
                return HealthStatus.unhealthy("Anthropic not initialized");
            }

            Map<String, Object> details = new HashMap<>();
            details.put("status", "healthy");
            details.put("baseUrl", baseUrl);
            details.put("apiKeyConfigured", true);

            if (modelId != null && !modelId.isEmpty()) {
                boolean modelCached = modelCache.containsKey(modelId);
                details.put("modelAvailable", modelCached || ready);
            }

            return new HealthStatus(true, "Healthy", 0, details);

        } catch (Exception e) {
            return HealthStatus.unhealthy("Health check failed: " + e.getMessage());
        }
    }

    // ========== Override Methods ==========

    @Override
    protected Map<String, Object> getAdditionalMetrics() {
        return Map.of("apiKeyConfigured", apiKey != null && !apiKey.isEmpty());
    }

    @Override
    protected ModelDescriptor.ModelStatus getModelStatus() {
        return apiKey != null && !apiKey.isEmpty() ? ModelDescriptor.ModelStatus.AVAILABLE
                : ModelDescriptor.ModelStatus.UNAVAILABLE;
    }

    // ========== Private Methods ==========

    private AnthropicApi getAnthropicApi() {
        if (anthropicApi == null) {
            throw new IllegalStateException("AnthropicApi not available. Please check Anthropic configuration.");
        }
        return anthropicApi;
    }
}
