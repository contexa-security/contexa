package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.properties.LlmProviderProperties;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;

import java.util.HashMap;
import java.util.Map;

/**
 * Ollama local model provider.
 * Extends BaseModelProvider to reuse common logic.
 * Creates models dynamically based on model ID.
 */
@Slf4j
public class OllamaModelProvider extends BaseModelProvider {

    @Autowired
    private LlmProviderProperties llmProviderProperties;

    @Autowired(required = false)
    private OllamaApi ollamaApi;

    // ========== Abstract Method Implementation ==========

    @Override
    public String getProviderName() {
        return "ollama";
    }

    @Override
    public String getDescription() {
        return "Local Ollama model provider for on-premise LLM deployment";
    }

    @Override
    protected String getProviderBaseUrl() {
        return llmProviderProperties.getOllama().getBaseUrl();
    }

    @Override
    protected boolean isProviderEnabled() {
        return llmProviderProperties.getOllama().isEnabled() && ollamaApi != null;
    }

    @Override
    protected void doInitialize(Map<String, Object> config) {
        // No additional initialization needed
    }

    @Override
    public int getPriority() {
        return 10;
    }

    @Override
    public ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config) {
        String modelId = descriptor.getModelId();

        if (hasCachedModel(modelId)) {
            return getCachedModel(modelId);
        }

        try {
            OllamaChatOptions.Builder optionsBuilder = OllamaChatOptions.builder()
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
                if (options.getRepetitionPenalty() != null) {
                    optionsBuilder.repeatPenalty(options.getRepetitionPenalty());
                }
            }

            if (config != null) {
                if (config.containsKey("temperature")) {
                    optionsBuilder.temperature((Double) config.get("temperature"));
                }
                if (config.containsKey("maxTokens")) {
                    optionsBuilder.numPredict((Integer) config.get("maxTokens"));
                }
            }

            OllamaChatOptions ollamaOptions = optionsBuilder.build();

            OllamaChatModel chatModel = OllamaChatModel.builder()
                    .ollamaApi(getOllamaApi())
                    .defaultOptions(ollamaOptions)
                    .build();

            cacheModel(modelId, chatModel);

            return chatModel;

        } catch (Exception e) {
            log.error("Failed to create Ollama model: {}", modelId, e);
            throw new RuntimeException("Failed to create Ollama model: " + modelId, e);
        }
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        try {
            if (restTemplate == null || baseUrl == null) {
                return HealthStatus.unhealthy("Ollama not initialized");
            }

            String versionUrl = baseUrl + "/api/version";
            ResponseEntity<Map> response = restTemplate.getForEntity(versionUrl, Map.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> details = new HashMap<>();
                details.put("status", "healthy");
                details.put("baseUrl", baseUrl);
                if (response.getBody() != null) {
                    details.put("version", response.getBody().get("version"));
                }

                if (modelId != null && !modelId.isEmpty()) {
                    boolean modelCached = modelCache.containsKey(modelId);
                    details.put("modelAvailable", modelCached || ready);

                    if (!modelCached && !ready) {
                        return new HealthStatus(true, "Ollama healthy but model not cached", 0, details);
                    }
                }

                return new HealthStatus(true, "Healthy", 0, details);
            } else {
                return HealthStatus.unhealthy("Ollama API returned status: " + response.getStatusCode());
            }
        } catch (RestClientException e) {
            return HealthStatus.unhealthy("Cannot connect to Ollama: " + e.getMessage());
        } catch (Exception e) {
            return HealthStatus.unhealthy("Health check failed: " + e.getMessage());
        }
    }

    // ========== Override Methods ==========

    @Override
    protected Map<String, Object> getAdditionalMetrics() {
        return Map.of("ollamaConnected", ready && baseUrl != null);
    }

    @Override
    protected ModelDescriptor.ModelStatus getModelStatus() {
        return ready ? ModelDescriptor.ModelStatus.AVAILABLE : ModelDescriptor.ModelStatus.UNAVAILABLE;
    }

    // ========== Private Methods ==========

    private OllamaApi getOllamaApi() {
        if (ollamaApi == null) {
            throw new IllegalStateException("OllamaApi not available. Please check Ollama configuration.");
        }
        return ollamaApi;
    }
}
