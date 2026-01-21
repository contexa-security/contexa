package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.config.ModelProviderProperties;
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
 */
@Slf4j
public class AnthropicModelProvider extends BaseModelProvider {

    @Value("${spring.ai.anthropic.api-key:}")
    private String apiKey;

    @Autowired(required = false)
    private AnthropicApi anthropicApi;

    // ========== 추상 메서드 구현 ==========

    @Override
    public String getProviderName() {
        return "anthropic";
    }

    @Override
    public String getDescription() {
        return "Anthropic Claude model provider for advanced AI capabilities";
    }

    @Override
    protected ModelProviderProperties.BaseProviderConfig getProviderConfig() {
        return modelProviderProperties.getAnthropic();
    }

    @Override
    protected void doInitialize(Map<String, Object> config) {
        if (apiKey == null || apiKey.isEmpty()) {
            log.warn("Anthropic API key is not set, but continuing");
        }
    }

    @Override
    public boolean isReady() {
        return ready && apiKey != null && !apiKey.isEmpty();
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType);
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
            ModelProviderProperties.AnthropicConfig anthropicConfig = modelProviderProperties.getAnthropic();
            ModelProviderProperties.ModelSpec modelSpec = null;

            if (anthropicConfig != null && anthropicConfig.getModels() != null) {
                modelSpec = anthropicConfig.getModels().get(modelId);
            }

            String apiModelId = modelId;
            if (modelSpec != null && modelSpec.getVersion() != null) {
                apiModelId = modelSpec.getVersion();
            }

            AnthropicChatOptions.Builder optionsBuilder = AnthropicChatOptions.builder()
                    .model(apiModelId);

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
                ModelProviderProperties.AnthropicConfig configForModel = modelProviderProperties.getAnthropic();
                boolean modelExists = configForModel != null &&
                        configForModel.getModels() != null &&
                        configForModel.getModels().containsKey(modelId);
                details.put("modelAvailable", modelExists);
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

    @Override
    protected Map<String, Object> getDefaultMetadata() {
        return Map.of(
                "cloud", true,
                "requiresApiKey", true);
    }

    // ========== Private Methods ==========

    private AnthropicApi getAnthropicApi() {
        if (anthropicApi == null) {
            throw new IllegalStateException("AnthropicApi not available. Please check Anthropic configuration.");
        }
        return anthropicApi;
    }
}
