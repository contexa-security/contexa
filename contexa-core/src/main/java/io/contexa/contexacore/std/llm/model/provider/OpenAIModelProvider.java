package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.config.ModelProviderProperties;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import io.contexa.contexacore.std.llm.model.ModelProvider;
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
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class OpenAIModelProvider implements ModelProvider {

    @Value("${spring.ai.openai.api-key:}")
    private String apiKey;

    @Autowired
    private ModelProviderProperties modelProviderProperties;

    @Autowired(required = false)
    private OpenAiChatModel defaultOpenAiChatModel;

    @Autowired(required = false)
    private OpenAiApi openAiApi;

    private String baseUrl;
    private RestTemplate restTemplate;
    private final Map<String, ModelDescriptor> modelCache = new ConcurrentHashMap<>();
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    private final Map<String, OpenAIModelInfo> discoveredModels = new ConcurrentHashMap<>();
    private boolean ready = false;

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

    @Override
    public String getProviderName() {
        return "openai";
    }

    @Override
    public String getDescription() {
        return "OpenAI model provider for GPT models";
    }

    @Override
    public List<ModelDescriptor> getAvailableModels() {
        List<ModelDescriptor> models = new ArrayList<>();

        ModelProviderProperties.OpenAIConfig openAIConfig = modelProviderProperties.getOpenai();
        if (openAIConfig != null && openAIConfig.getModels() != null) {
            for (Map.Entry<String, ModelProviderProperties.ModelSpec> entry :
                    openAIConfig.getModels().entrySet()) {
                String modelId = entry.getKey();
                ModelProviderProperties.ModelSpec spec = entry.getValue();

                if (!modelCache.containsKey(modelId)) {
                    ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                    modelCache.put(modelId, descriptor);
                }
                models.add(modelCache.get(modelId));
            }
        }

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
    public ModelDescriptor getModelDescriptor(String modelId) {
        if (modelCache.containsKey(modelId)) {
            return modelCache.get(modelId);
        }

        ModelProviderProperties.OpenAIConfig openAIConfig = modelProviderProperties.getOpenai();
        if (openAIConfig != null && openAIConfig.getModels() != null) {
            ModelProviderProperties.ModelSpec spec = openAIConfig.getModels().get(modelId);
            if (spec != null) {
                ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                modelCache.put(modelId, descriptor);
                return descriptor;
            }
        }

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
    public ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config) {
        String modelId = descriptor.getModelId();

        if (modelInstances.containsKey(modelId)) {
            return modelInstances.get(modelId);
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

            modelInstances.put(modelId, chatModel);
            
            return chatModel;

        } catch (Exception e) {
            log.error("OpenAI 모델 생성 실패: {}", modelId, e);
            throw new RuntimeException("Failed to create OpenAI model: " + modelId, e);
        }
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType) ||
               ModelType.EMBEDDING.equals(modelType);
    }

    @Override
    public boolean supportsModel(String modelId) {
        
        ModelProviderProperties.OpenAIConfig openAIConfig = modelProviderProperties.getOpenai();
        if (openAIConfig != null && openAIConfig.getModels() != null &&
            openAIConfig.getModels().containsKey(modelId)) {
            return true;
        }

        if (modelCache.containsKey(modelId)) {
            return true;
        }

        return isGPTModel(modelId);
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

    @Override
    public void initialize(Map<String, Object> config) {
        
        try {
            
            ModelProviderProperties.OpenAIConfig openAIConfig = modelProviderProperties.getOpenai();
            if (openAIConfig != null && openAIConfig.isEnabled()) {
                this.baseUrl = openAIConfig.getBaseUrl();
            } else {
                log.warn("OpenAI가 비활성화되어 있거나 설정이 없습니다");
                ready = false;
                return;
            }

            if (apiKey == null || apiKey.isEmpty()) {
                log.warn("OpenAI API 키가 설정되지 않았지만 계속 진행합니다");
                
            }

            this.restTemplate = new RestTemplate();

            boolean modelsLoaded = false;
            if (apiKey != null && !apiKey.isEmpty()) {
                modelsLoaded = loadModelsFromOpenAI();
            }

            if (!modelsLoaded) {
                log.warn("OpenAI 서버에서 모델을 로드하지 못했지만, 설정 파일의 모델 정의를 사용합니다");
            }

            ready = true; 
                    } catch (Exception e) {
            log.error("OpenAIModelProvider 초기화 실패", e);
            ready = false;
        }
    }

    @Override
    public void shutdown() {
                modelInstances.clear();
        modelCache.clear();
        discoveredModels.clear();
        ready = false;
    }

    @Override
    public boolean isReady() {
        return ready; 
    }

    @Override
    public void refreshModels() {
                loadModelsFromOpenAI();
    }

    @Override
    public int getPriority() {
        return 25; 
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("cachedModels", modelCache.size());
        metrics.put("activeInstances", modelInstances.size());
        metrics.put("discoveredModels", discoveredModels.size());
        metrics.put("ready", ready);
        metrics.put("apiKeyConfigured", apiKey != null && !apiKey.isEmpty());
        return metrics;
    }

    private boolean loadModelsFromOpenAI() {
        if (restTemplate == null || baseUrl == null) {
            log.warn("RestTemplate 또는 baseUrl이 설정되지 않아 모델 목록을 로드할 수 없습니다");
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

                        if (isGPTModel(modelId) && isValidOpenAIModel(modelId)) {
                            discoveredModels.put(modelId, model);
                                                    }
                    }

                                        return true;
                }
            } else {
                log.warn("OpenAI API 응답이 비정상입니다: {}", response.getStatusCode());
            }
        } catch (RestClientException e) {
            log.warn("OpenAI 서버 연결 실패 (정상적인 경우일 수 있음): {}", e.getMessage());
        } catch (Exception e) {
            log.error("OpenAI 모델 목록 로드 중 오류 발생", e);
        }
        return false;
    }

    private boolean isGPTModel(String modelId) {
        if (modelId == null) return false;
        String lower = modelId.toLowerCase();
        return lower.startsWith("gpt-") ||
               lower.startsWith("text-davinci") ||
               lower.startsWith("text-curie") ||
               lower.startsWith("text-babbage") ||
               lower.startsWith("text-ada");
    }

    private boolean isValidOpenAIModel(String modelId) {
        if (modelId == null) return false;
        String lower = modelId.toLowerCase();

        return lower.matches("gpt-4(-\\d{4})?(-preview)?") ||  
               lower.matches("gpt-4-turbo(-\\d{4}-\\d{2}-\\d{2})?(-preview)?") || 
               lower.matches("gpt-4o(-mini)?(-\\d{4}-\\d{2}-\\d{2})?") || 
               lower.matches("gpt-3\\.5-turbo(-\\d{4})?(-16k)?") || 
               lower.matches("text-(davinci|curie|babbage|ada)(-\\d{3})?") || 
               lower.equals("gpt-4-vision-preview") || 
               lower.equals("gpt-4-1106-preview"); 
    }

    private ModelDescriptor createModelDescriptorFromSpec(String modelId, ModelProviderProperties.ModelSpec spec) {
        var capBuilder = ModelDescriptor.ModelCapabilities.builder()
            .streaming(spec.getCapabilities().getStreaming())
            .toolCalling(spec.getCapabilities().getToolCalling())
            .functionCalling(spec.getCapabilities().getFunctionCalling())
            .vision(spec.getCapabilities().getVision())
            .multiModal(spec.getCapabilities().getMultiModal())
            .maxTokens(spec.getCapabilities().getMaxTokens())
            .contextWindow(spec.getCapabilities().getContextWindow())
            .supportsSystemMessage(spec.getCapabilities().getSupportsSystemMessage());

        if (spec.getCapabilities().getMaxOutputTokens() != null) {
            capBuilder.maxOutputTokens(spec.getCapabilities().getMaxOutputTokens());
        } else {
            capBuilder.maxOutputTokens(4096); 
        }

        ModelDescriptor.ThroughputLevel throughput = ModelDescriptor.ThroughputLevel.valueOf(
            spec.getPerformance().getThroughputLevel());

        return ModelDescriptor.builder()
            .modelId(modelId)
            .displayName(spec.getDisplayName())
            .provider(getProviderName())
            .version(spec.getVersion())
            .modelSize(spec.getModelSize())
            .tier(spec.getTier())
            .capabilities(capBuilder.build())
            .performance(ModelDescriptor.PerformanceProfile.builder()
                .latency(spec.getPerformance().getLatencyMs())
                .throughput(throughput)
                .concurrency(spec.getPerformance().getConcurrency())
                .recommendedTimeout(spec.getPerformance().getRecommendedTimeoutMs())
                .performanceScore(spec.getPerformance().getPerformanceScore())
                .build())
            .cost(ModelDescriptor.CostProfile.builder()
                .costPerInputToken(spec.getCost().getCostPerInputToken())
                .costPerOutputToken(spec.getCost().getCostPerOutputToken())
                .costEfficiency(spec.getCost().getCostEfficiency())
                .build())
            .options(ModelDescriptor.ModelOptions.builder()
                .temperature(spec.getOptions().getTemperature())
                .topP(spec.getOptions().getTopP())
                .build())
            .status(apiKey != null && !apiKey.isEmpty() ?
                ModelDescriptor.ModelStatus.AVAILABLE :
                ModelDescriptor.ModelStatus.UNAVAILABLE)
            .metadata(spec.getMetadata() != null ? spec.getMetadata() : Map.of(
                "cloud", true,
                "requiresApiKey", true
            ))
            .build();
    }

    private ModelDescriptor createModelDescriptorFromDiscovery(String modelId, OpenAIModelInfo info) {
        
        int tier = estimateTierFromModelId(modelId);

        ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
            modelProviderProperties.getTierDefaults(tier);

        if (tierDefaults == null) {
            
            tierDefaults = new ModelProviderProperties.DefaultSpecs.TierDefaults();
            tierDefaults.setTimeoutMs(5000);
            tierDefaults.setTemperature(0.5);
            tierDefaults.setMaxTokens(4096);
            tierDefaults.setContextWindow(4096);
            tierDefaults.setPerformanceScore(75.0);
            tierDefaults.setLatencyMs(1000);
            tierDefaults.setConcurrency(50);
        }

        boolean supportsFunctions = modelId.contains("gpt-4") || modelId.contains("gpt-3.5-turbo");
        boolean supportsVision = modelId.contains("vision");
        int maxTokens = estimateMaxTokens(modelId);

        return ModelDescriptor.builder()
            .modelId(modelId)
            .displayName(modelId)
            .provider(getProviderName())
            .version(modelId)
            .modelSize("N/A")
            .tier(tier)
            .capabilities(ModelDescriptor.ModelCapabilities.builder()
                .streaming(true)
                .toolCalling(supportsFunctions)
                .functionCalling(supportsFunctions)
                .vision(supportsVision)
                .multiModal(supportsVision)
                .maxTokens(maxTokens)
                .contextWindow(maxTokens)
                .supportsSystemMessage(true)
                .maxOutputTokens(4096)
                .build())
            .performance(ModelDescriptor.PerformanceProfile.builder()
                .latency(tierDefaults.getLatencyMs())
                .throughput(tier == 1 ?
                    ModelDescriptor.ThroughputLevel.HIGH :
                    tier == 2 ?
                    ModelDescriptor.ThroughputLevel.MEDIUM :
                    ModelDescriptor.ThroughputLevel.LOW)
                .concurrency(tierDefaults.getConcurrency())
                .recommendedTimeout(tierDefaults.getTimeoutMs())
                .performanceScore(tierDefaults.getPerformanceScore())
                .build())
            .cost(ModelDescriptor.CostProfile.builder()
                .costPerInputToken(estimateCostPerInputToken(modelId))
                .costPerOutputToken(estimateCostPerOutputToken(modelId))
                .costEfficiency(estimateCostEfficiency(modelId))
                .build())
            .options(ModelDescriptor.ModelOptions.builder()
                .temperature(tierDefaults.getTemperature())
                .topP(0.9)
                .build())
            .status(ModelDescriptor.ModelStatus.AVAILABLE)
            .metadata(Map.of(
                "cloud", true,
                "dynamicallyDiscovered", true,
                "requiresApiKey", true
            ))
            .build();
    }

    private int estimateTierFromModelId(String modelId) {
        if (modelId == null) return 2;

        String lower = modelId.toLowerCase();

        if (lower.contains("gpt-4")) {
            return 3;
        }

        if (lower.contains("gpt-3.5-turbo")) {
            return 2;
        }

        return 1;
    }

    private int estimateMaxTokens(String modelId) {
        if (modelId == null) return 4096;

        String lower = modelId.toLowerCase();

        if (lower.contains("gpt-4-turbo") || lower.contains("gpt-4-1106")) {
            return 128000;
        } else if (lower.contains("gpt-4-32k")) {
            return 32768;
        } else if (lower.contains("gpt-4")) {
            return 8192;
        } else if (lower.contains("gpt-3.5-turbo-16k")) {
            return 16385;
        } else if (lower.contains("gpt-3.5-turbo")) {
            return 4096;
        }

        return 4096;
    }

    private double estimateCostPerInputToken(String modelId) {
        if (modelId == null) return 0.00001;

        String lower = modelId.toLowerCase();

        if (lower.contains("gpt-4-turbo") || lower.contains("gpt-4-1106")) {
            return 0.00001;
        } else if (lower.contains("gpt-4-32k")) {
            return 0.00006;
        } else if (lower.contains("gpt-4")) {
            return 0.00003;
        } else if (lower.contains("gpt-3.5-turbo-16k")) {
            return 0.000003;
        } else if (lower.contains("gpt-3.5-turbo")) {
            return 0.0000005;
        }

        return 0.00001;
    }

    private double estimateCostPerOutputToken(String modelId) {
        if (modelId == null) return 0.00003;

        String lower = modelId.toLowerCase();

        if (lower.contains("gpt-4-turbo") || lower.contains("gpt-4-1106")) {
            return 0.00003;
        } else if (lower.contains("gpt-4-32k")) {
            return 0.00012;
        } else if (lower.contains("gpt-4")) {
            return 0.00006;
        } else if (lower.contains("gpt-3.5-turbo-16k")) {
            return 0.000004;
        } else if (lower.contains("gpt-3.5-turbo")) {
            return 0.0000015;
        }

        return 0.00003;
    }

    private double estimateCostEfficiency(String modelId) {
        if (modelId == null) return 50.0;

        String lower = modelId.toLowerCase();

        if (lower.contains("gpt-3.5-turbo")) {
            return 80.0; 
        } else if (lower.contains("gpt-4-turbo")) {
            return 60.0;
        } else if (lower.contains("gpt-4")) {
            return 40.0; 
        }

        return 50.0;
    }

    private OpenAiApi getOpenAiApi() {
        if (openAiApi == null) {
            throw new IllegalStateException("OpenAiApi not available. Please check OpenAI configuration.");
        }
        return openAiApi;
    }
}