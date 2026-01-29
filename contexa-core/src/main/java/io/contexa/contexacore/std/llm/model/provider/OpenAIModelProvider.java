package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.HashMap;
import java.util.Map;

/**
 * OpenAI GPT model provider.
 * Extends BaseModelProvider to reuse common logic.
 * Creates models dynamically based on model ID.
 */
@Slf4j
public class OpenAIModelProvider extends BaseModelProvider {

    @Value("${spring.ai.openai.api-key:}")
    private String apiKey;

    @Value("${spring.ai.openai.base-url:https://api.openai.com}")
    private String openaiBaseUrl;

    @Value("${spring.ai.openai.enabled:true}")
    private boolean openaiEnabled;

    @Autowired(required = false)
    private OpenAiApi openAiApi;

    // ========== Abstract Method Implementation ==========

    @Override
    public String getProviderName() {
        return "openai";
    }

    @Override
    public String getDescription() {
        return "OpenAI model provider for GPT models";
    }

    @Override
    protected String getProviderBaseUrl() {
        return openaiBaseUrl;
    }

    @Override
    protected boolean isProviderEnabled() {
        return openaiEnabled && apiKey != null && !apiKey.isEmpty();
    }

    @Override
    protected void doInitialize(Map<String, Object> config) {
        if (apiKey == null || apiKey.isEmpty()) {
            log.warn("OpenAI API key is not set, but continuing");
        }
    }

    @Override
    public boolean isReady() {
        return ready && apiKey != null && !apiKey.isEmpty();
    }

    @Override
    public int getPriority() {
        return 25;
    }

    @Override
    public ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config) {
        String modelId = descriptor.getModelId();

        if (hasCachedModel(modelId)) {
            return getCachedModel(modelId);
        }

        try {
            OpenAiChatOptions.Builder optionsBuilder = OpenAiChatOptions.builder()
                    .model(modelId);

            if (descriptor.getOptions() != null) {
                ModelDescriptor.ModelOptions options = descriptor.getOptions();
                if (options.getTemperature() != null) {
                    optionsBuilder.temperature(options.getTemperature());
                }
                if (options.getTopP() != null) {
                    optionsBuilder.topP(options.getTopP());
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
                if (config.containsKey("topP")) {
                    optionsBuilder.topP((Double) config.get("topP"));
                }
                if (config.containsKey("frequencyPenalty")) {
                    optionsBuilder.frequencyPenalty((Double) config.get("frequencyPenalty"));
                }
                if (config.containsKey("presencePenalty")) {
                    optionsBuilder.presencePenalty((Double) config.get("presencePenalty"));
                }
            }

            OpenAiChatOptions openAiOptions = optionsBuilder.build();

            if (!isReady()) {
                throw new ModelSelectionException("OpenAI API not configured. Please set OPENAI_API_KEY", modelId);
            }

            OpenAiChatModel chatModel = OpenAiChatModel.builder()
                    .openAiApi(getOpenAiApi())
                    .defaultOptions(openAiOptions)
                    .build();

            cacheModel(modelId, chatModel);

            return chatModel;

        } catch (Exception e) {
            log.error("Failed to create OpenAI model: {}", modelId, e);
            throw new RuntimeException("Failed to create OpenAI model: " + modelId, e);
        }
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        try {
            if (apiKey == null || apiKey.isEmpty()) {
                return HealthStatus.unhealthy("API key not configured");
            }

            if (baseUrl == null) {
                return HealthStatus.unhealthy("OpenAI not initialized");
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

    private OpenAiApi getOpenAiApi() {
        if (openAiApi == null) {
            throw new IllegalStateException("OpenAiApi not available. Please check OpenAI configuration.");
        }
        return openAiApi;
    }
}
