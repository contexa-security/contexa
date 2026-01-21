package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.config.ModelProviderProperties;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OpenAI GPT model provider.
 * Extends BaseModelProvider to reuse common logic.
 * Includes functionality to dynamically discover models from the OpenAI API.
 */
@Slf4j
public class OpenAIModelProvider extends BaseModelProvider {

    @Value("${spring.ai.openai.api-key:}")
    private String apiKey;

    @Autowired(required = false)
    private OpenAiApi openAiApi;

    private final Map<String, OpenAIModelInfo> discoveredModels = new ConcurrentHashMap<>();

    // ========== Inner Classes ==========

    @Data
    public static class OpenAIModelsResponse {
        private List<OpenAIModelInfo> data;
        private String object;
    }

    @Data
    public static class OpenAIModelInfo {
        private String id;
        private String object;
        private Long created;
        private String owned_by;
        private List<Permission> permission;
        private String root;
        private String parent;
    }

    @Data
    public static class Permission {
        private String id;
        private String object;
        private Long created;
        private boolean allow_create_engine;
        private boolean allow_sampling;
        private boolean allow_logprobs;
        private boolean allow_search_indices;
        private boolean allow_view;
        private boolean allow_fine_tuning;
        private String organization;
        private String group;
        private boolean is_blocking;
    }

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
    protected ModelProviderProperties.BaseProviderConfig getProviderConfig() {
        return modelProviderProperties.getOpenai();
    }

    @Override
    protected void doInitialize(Map<String, Object> config) {
        if (apiKey == null || apiKey.isEmpty()) {
            log.warn("OpenAI API key is not set, but continuing");
        }

        boolean modelsLoaded = false;
        if (apiKey != null && !apiKey.isEmpty()) {
            modelsLoaded = loadModelsFromOpenAI();
        }

        if (!modelsLoaded) {
            log.warn("Failed to load models from OpenAI server, using model definitions from configuration file");
        }
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType) ||
                ModelType.EMBEDDING.equals(modelType);
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

            if (restTemplate == null || baseUrl == null) {
                return HealthStatus.unhealthy("OpenAI not initialized");
            }

            String modelsUrl = baseUrl + "/v1/models";

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + apiKey);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            try {
                ResponseEntity<OpenAIModelsResponse> response = restTemplate.exchange(
                        modelsUrl, HttpMethod.GET, entity, OpenAIModelsResponse.class);

                if (response.getStatusCode() == HttpStatus.OK) {
                    Map<String, Object> details = new HashMap<>();
                    details.put("status", "healthy");
                    details.put("baseUrl", baseUrl);
                    details.put("apiKeyConfigured", true);

                    if (modelId != null && !modelId.isEmpty()) {
                        boolean modelExists = discoveredModels.containsKey(modelId) ||
                                (modelProviderProperties.getOpenai() != null &&
                                        modelProviderProperties.getOpenai().getModels().containsKey(modelId));
                        details.put("modelAvailable", modelExists);
                    }

                    if (response.getBody() != null && response.getBody().getData() != null) {
                        details.put("availableModels", response.getBody().getData().size());
                    }

                    return new HealthStatus(true, "Healthy", 0, details);
                }

                return HealthStatus.unhealthy("OpenAI API returned status: " + response.getStatusCode());

            } catch (RestClientException e) {
                if (e.getMessage() != null && e.getMessage().contains("401")) {
                    return HealthStatus.unhealthy("Invalid API key");
                } else if (e.getMessage() != null && e.getMessage().contains("429")) {
                    Map<String, Object> details = new HashMap<>();
                    details.put("status", "rate_limited");
                    details.put("baseUrl", baseUrl);
                    return new HealthStatus(true, "Healthy but rate limited", 0, details);
                }
                return HealthStatus.unhealthy("API check failed: " + e.getMessage());
            }
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
        loadModelsFromOpenAI();
    }

    @Override
    public boolean supportsModel(String modelId) {
        return super.supportsModel(modelId) ||
                modelCache.containsKey(modelId) ||
                isGPTModel(modelId);
    }

    @Override
    protected List<ModelDescriptor> getDiscoveredModels() {
        List<ModelDescriptor> models = new ArrayList<>();
        for (Map.Entry<String, OpenAIModelInfo> entry : discoveredModels.entrySet()) {
            String modelId = entry.getKey();
            if (!modelCache.containsKey(modelId) && isGPTModel(modelId)) {
                ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, entry.getValue());
                modelCache.put(modelId, descriptor);
                models.add(descriptor);
            }
        }
        return models;
    }

    @Override
    protected ModelDescriptor findDiscoveredModel(String modelId) {
        OpenAIModelInfo info = discoveredModels.get(modelId);
        if (info != null) {
            ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, info);
            modelCache.put(modelId, descriptor);
            return descriptor;
        }

        loadModelsFromOpenAI();
        info = discoveredModels.get(modelId);
        if (info != null) {
            ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, info);
            modelCache.put(modelId, descriptor);
            return descriptor;
        }

        return null;
    }

    @Override
    protected Map<String, Object> getAdditionalMetrics() {
        return Map.of(
                "discoveredModels", discoveredModels.size(),
                "apiKeyConfigured", apiKey != null && !apiKey.isEmpty());
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

    private boolean loadModelsFromOpenAI() {
        if (restTemplate == null || baseUrl == null) {
            log.warn("RestTemplate or baseUrl not set, cannot load model list");
            return false;
        }

        try {
            String modelsUrl = baseUrl + "/v1/models";

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + apiKey);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<OpenAIModelsResponse> response = restTemplate.exchange(
                    modelsUrl, HttpMethod.GET, entity, OpenAIModelsResponse.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                OpenAIModelsResponse modelsResponse = response.getBody();

                if (modelsResponse.getData() != null) {
                    discoveredModels.clear();

                    for (OpenAIModelInfo model : modelsResponse.getData()) {
                        String modelId = model.getId();

                        if (isGPTModel(modelId)) {
                            discoveredModels.put(modelId, model);
                        }
                    }

                    return true;
                }
            } else {
                log.warn("Abnormal OpenAI API response: {}", response.getStatusCode());
            }
        } catch (RestClientException e) {
            log.warn("OpenAI server connection failed (might be normal): {}", e.getMessage());
        } catch (Exception e) {
            log.error("Error loading OpenAI model list", e);
        }
        return false;
    }

    private boolean isGPTModel(String modelId) {
        if (modelId == null)
            return false;
        String lower = modelId.toLowerCase();
        return lower.startsWith("gpt-") ||
                lower.startsWith("o1") ||
                lower.startsWith("text-davinci") ||
                lower.startsWith("text-curie") ||
                lower.startsWith("text-babbage") ||
                lower.startsWith("text-ada");
    }

    private ModelDescriptor createModelDescriptorFromDiscovery(String modelId, OpenAIModelInfo info) {
        int tier = estimateTierFromModelId(modelId);

        ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults = modelProviderProperties.getTierDefaults(tier);

        // OpenAI 모델의 경우 모델명에서 기능을 추론할 수 있음
        boolean supportsFunctions = modelId.contains("gpt-4") || modelId.contains("gpt-3.5-turbo") || modelId.contains("o1");
        boolean supportsVision = modelId.contains("vision") || modelId.contains("gpt-4o");

        // TierDefaults가 없으면 최소 필수 정보만으로 ModelDescriptor 생성
        // 상세 정보(performance, cost, options)는 알 수 없으므로 설정하지 않음
        if (tierDefaults == null) {
            return ModelDescriptor.builder()
                    .modelId(modelId)
                    .displayName(modelId)
                    .provider(getProviderName())
                    .version(modelId)
                    .tier(tier)
                    .capabilities(ModelDescriptor.ModelCapabilities.builder()
                            .streaming(true)
                            .toolCalling(supportsFunctions)
                            .functionCalling(supportsFunctions)
                            .vision(supportsVision)
                            .multiModal(supportsVision)
                            .supportsSystemMessage(true)
                            .build())
                    .status(ModelDescriptor.ModelStatus.AVAILABLE)
                    .metadata(Map.of(
                            "cloud", true,
                            "dynamicallyDiscovered", true,
                            "requiresApiKey", true))
                    .build();
        }

        return ModelDescriptor.builder()
                .modelId(modelId)
                .displayName(modelId)
                .provider(getProviderName())
                .version(modelId)
                .tier(tier)
                .capabilities(ModelDescriptor.ModelCapabilities.builder()
                        .streaming(true)
                        .toolCalling(supportsFunctions)
                        .functionCalling(supportsFunctions)
                        .vision(supportsVision)
                        .multiModal(supportsVision)
                        .maxTokens(tierDefaults.getMaxTokens())
                        .contextWindow(tierDefaults.getContextWindow())
                        .supportsSystemMessage(true)
                        .maxOutputTokens(tierDefaults.getMaxTokens())
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
                        "cloud", true,
                        "dynamicallyDiscovered", true,
                        "requiresApiKey", true))
                .build();
    }

    private int estimateTierFromModelId(String modelId) {
        if (modelId == null)
            return 2;

        String lower = modelId.toLowerCase();

        if (lower.contains("gpt-4") || lower.contains("o1")) {
            return 3;
        }

        if (lower.contains("gpt-3.5-turbo")) {
            return 2;
        }

        return 1;
    }

    private OpenAiApi getOpenAiApi() {
        if (openAiApi == null) {
            throw new IllegalStateException("OpenAiApi not available. Please check OpenAI configuration.");
        }
        return openAiApi;
    }
}
