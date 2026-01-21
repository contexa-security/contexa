package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.config.ModelProviderProperties;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.ai.ollama.api.OllamaOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ollama local model provider.
 * Extends BaseModelProvider to reuse common logic.
 * Includes functionality to dynamically discover models from the local Ollama
 * server.
 */
@Slf4j
public class OllamaModelProvider extends BaseModelProvider {

    @Autowired(required = false)
    private OllamaApi ollamaApi;

    private final Map<String, OllamaModelDetails> discoveredModels = new ConcurrentHashMap<>();

    // ========== Inner Classes ==========

    @Data
    public static class OllamaTagsResponse {
        private List<OllamaModel> models;
    }

    @Data
    public static class OllamaModel {
        private String name;
        private String digest;
        private Long size;
        private String modified_at;
        private OllamaModelDetails details;
    }

    @Data
    public static class OllamaModelDetails {
        private String format;
        private String family;
        private List<String> families;
        private String parameter_size;
        private String quantization_level;
    }

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
    protected ModelProviderProperties.BaseProviderConfig getProviderConfig() {
        return modelProviderProperties.getOllama();
    }

    @Override
    protected void doInitialize(Map<String, Object> config) {
        boolean modelsLoaded = loadModelsFromOllama();
        if (!modelsLoaded) {
            log.warn("Failed to load models from Ollama server, using model definitions from configuration file");
        }
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType) ||
                ModelType.EMBEDDING.equals(modelType);
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
            OllamaOptions.Builder optionsBuilder = OllamaOptions.builder()
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

            OllamaOptions ollamaOptions = optionsBuilder.build();

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
                    boolean modelExists = discoveredModels.containsKey(modelId) ||
                            (modelProviderProperties.getOllama() != null &&
                                    modelProviderProperties.getOllama().getModels().containsKey(modelId));
                    details.put("modelAvailable", modelExists);

                    if (!modelExists) {
                        return new HealthStatus(true, "Ollama healthy but model not found", 0, details);
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
    public void shutdown() {
        super.shutdown();
        discoveredModels.clear();
    }

    @Override
    public void refreshModels() {
        loadModelsFromOllama();
    }

    @Override
    public boolean supportsModel(String modelId) {
        return super.supportsModel(modelId) || discoveredModels.containsKey(modelId);
    }

    @Override
    protected List<ModelDescriptor> getDiscoveredModels() {
        List<ModelDescriptor> models = new ArrayList<>();
        for (Map.Entry<String, OllamaModelDetails> entry : discoveredModels.entrySet()) {
            String modelId = entry.getKey();
            if (!modelCache.containsKey(modelId)) {
                ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, entry.getValue());
                modelCache.put(modelId, descriptor);
            }
            models.add(modelCache.get(modelId));
        }
        return models;
    }

    @Override
    protected ModelDescriptor findDiscoveredModel(String modelId) {
        OllamaModelDetails details = discoveredModels.get(modelId);
        if (details != null) {
            ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, details);
            modelCache.put(modelId, descriptor);
            return descriptor;
        }

        loadModelsFromOllama();
        details = discoveredModels.get(modelId);
        if (details != null) {
            ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, details);
            modelCache.put(modelId, descriptor);
            return descriptor;
        }

        return null;
    }

    @Override
    protected Map<String, Object> getAdditionalMetrics() {
        return Map.of(
                "discoveredModels", discoveredModels.size(),
                "ollamaConnected", ready && baseUrl != null);
    }

    @Override
    protected ModelDescriptor.ModelStatus getModelStatus() {
        return ready ? ModelDescriptor.ModelStatus.AVAILABLE : ModelDescriptor.ModelStatus.UNAVAILABLE;
    }

    @Override
    protected Map<String, Object> getDefaultMetadata() {
        return Map.of(
                "local", true,
                "requiresGPU", false);
    }

    // ========== Private Methods ==========

    private boolean loadModelsFromOllama() {
        if (restTemplate == null || baseUrl == null) {
            log.warn("RestTemplate or baseUrl not set, cannot load model list");
            return false;
        }

        try {
            String tagsUrl = baseUrl + "/api/tags";

            ResponseEntity<OllamaTagsResponse> response = restTemplate.getForEntity(
                    tagsUrl, OllamaTagsResponse.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                OllamaTagsResponse tagsResponse = response.getBody();

                if (tagsResponse.getModels() != null) {
                    discoveredModels.clear();

                    for (OllamaModel model : tagsResponse.getModels()) {
                        String modelName = model.getName();
                        OllamaModelDetails details = model.getDetails();

                        if (details == null) {
                            details = new OllamaModelDetails();
                            details.setParameter_size("unknown");
                        }

                        discoveredModels.put(modelName, details);
                    }

                    return true;
                }
            } else {
                log.warn("Abnormal Ollama API response: {}", response.getStatusCode());
            }
        } catch (RestClientException e) {
            log.warn("Ollama server connection failed (might be normal): {}", e.getMessage());
        } catch (Exception e) {
            log.error("Error loading Ollama model list", e);
        }
        return false;
    }

    private ModelDescriptor createModelDescriptorFromDiscovery(String modelId, OllamaModelDetails details) {
        int tier = estimateTierFromSize(details.getParameter_size());

        ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults = modelProviderProperties.getTierDefaults(tier);

        // TierDefaults가 없으면 최소 필수 정보만으로 ModelDescriptor 생성
        // 상세 정보(capabilities, performance, cost, options)는 알 수 없으므로 설정하지 않음
        if (tierDefaults == null) {
            return ModelDescriptor.builder()
                    .modelId(modelId)
                    .displayName(modelId)
                    .provider(getProviderName())
                    .version(modelId.contains(":") ? modelId.split(":")[1] : "latest")
                    .modelSize(details.getParameter_size() != null ? details.getParameter_size() : "unknown")
                    .tier(tier)
                    .status(ModelDescriptor.ModelStatus.AVAILABLE)
                    .metadata(Map.of(
                            "local", true,
                            "dynamicallyDiscovered", true))
                    .build();
        }

        return ModelDescriptor.builder()
                .modelId(modelId)
                .displayName(modelId)
                .provider(getProviderName())
                .version(modelId.contains(":") ? modelId.split(":")[1] : "latest")
                .modelSize(details.getParameter_size() != null ? details.getParameter_size() : "unknown")
                .tier(tier)
                .capabilities(ModelDescriptor.ModelCapabilities.builder()
                        .streaming(true)
                        .toolCalling(false)
                        .functionCalling(false)
                        .vision(modelId.contains("vision"))
                        .multiModal(false)
                        .maxTokens(tierDefaults.getMaxTokens())
                        .contextWindow(tierDefaults.getContextWindow())
                        .supportsSystemMessage(true)
                        .build())
                .performance(ModelDescriptor.PerformanceProfile.builder()
                        .latency(tierDefaults.getLatencyMs())
                        .throughput(tier == 1 ? ModelDescriptor.ThroughputLevel.HIGH
                                : tier == 2 ? ModelDescriptor.ThroughputLevel.MEDIUM
                                        : ModelDescriptor.ThroughputLevel.LOW)
                        .concurrency(tierDefaults.getConcurrency())
                        .recommendedTimeout(tierDefaults.getTimeoutMs())
                        .performanceScore(tierDefaults.getPerformanceScore())
                        .build())
                .options(ModelDescriptor.ModelOptions.builder()
                        .temperature(tierDefaults.getTemperature())
                        .build())
                .status(ModelDescriptor.ModelStatus.AVAILABLE)
                .metadata(Map.of(
                        "local", true,
                        "dynamicallyDiscovered", true,
                        "requiresGPU", !modelId.contains("tiny")))
                .build();
    }

    private int estimateTierFromSize(String parameterSize) {
        if (parameterSize == null || parameterSize.equals("unknown")) {
            return 2;
        }

        String sizeStr = parameterSize.toLowerCase()
                .replace("b", "")
                .replace("billion", "")
                .replace("million", "")
                .replace("m", "")
                .trim();

        try {
            double size = Double.parseDouble(sizeStr);

            if (parameterSize.toLowerCase().contains("m")) {
                size = size / 1000.0;
            }

            // Tier 경계값 (Ollama 모델 크기 기준)
            // 5B 미만 = Tier 1 (소형 모델)
            // 20B 미만 = Tier 2 (중형 모델)
            // 20B 이상 = Tier 3 (대형 모델)
            double tier1Max = 5.0;
            double tier2Max = 20.0;

            if (size < tier1Max) {
                return 1;
            } else if (size < tier2Max) {
                return 2;
            } else {
                return 3;
            }
        } catch (NumberFormatException e) {
            return 2;
        }
    }

    private OllamaApi getOllamaApi() {
        if (ollamaApi == null) {
            throw new IllegalStateException("OllamaApi not available. Please check Ollama configuration.");
        }
        return ollamaApi;
    }
}
