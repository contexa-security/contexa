package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.config.ModelProviderProperties;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import io.contexa.contexacore.std.llm.model.ModelProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
public class AnthropicModelProvider implements ModelProvider {

    @Value("${spring.ai.anthropic.api-key:}")
    private String apiKey;

    @Autowired
    private ModelProviderProperties modelProviderProperties;

    @Autowired(required = false)
    private AnthropicChatModel defaultAnthropicChatModel;

    @Autowired(required = false)
    private AnthropicApi anthropicApi;

    private String baseUrl;
    private RestTemplate restTemplate;
    private final Map<String, ModelDescriptor> modelCache = new ConcurrentHashMap<>();
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    private boolean ready = false;

    @Override
    public String getProviderName() {
        return "anthropic";
    }

    @Override
    public String getDescription() {
        return "Anthropic Claude model provider for advanced AI capabilities";
    }

    @Override
    public List<ModelDescriptor> getAvailableModels() {
        List<ModelDescriptor> models = new ArrayList<>();

        
        ModelProviderProperties.AnthropicConfig anthropicConfig = modelProviderProperties.getAnthropic();
        if (anthropicConfig != null && anthropicConfig.getModels() != null) {
            for (Map.Entry<String, ModelProviderProperties.ModelSpec> entry :
                    anthropicConfig.getModels().entrySet()) {
                String modelId = entry.getKey();
                ModelProviderProperties.ModelSpec spec = entry.getValue();

                if (!modelCache.containsKey(modelId)) {
                    ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                    modelCache.put(modelId, descriptor);
                }
                models.add(modelCache.get(modelId));
            }
        }

        return models;
    }

    @Override
    public ModelDescriptor getModelDescriptor(String modelId) {
        if (modelCache.containsKey(modelId)) {
            return modelCache.get(modelId);
        }

        
        ModelProviderProperties.AnthropicConfig anthropicConfig = modelProviderProperties.getAnthropic();
        if (anthropicConfig != null && anthropicConfig.getModels() != null) {
            ModelProviderProperties.ModelSpec spec = anthropicConfig.getModels().get(modelId);
            if (spec != null) {
                ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                modelCache.put(modelId, descriptor);
                return descriptor;
            }
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
                throw new ModelSelectionException("Anthropic API not configured. Please set ANTHROPIC_API_KEY", modelId);
            }

            
            AnthropicChatModel chatModel = AnthropicChatModel.builder()
                .anthropicApi(getAnthropicApi())
                .defaultOptions(anthropicOptions)
                .build();

            modelInstances.put(modelId, chatModel);
            log.info("Anthropic 모델 생성 완료: {}", modelId);

            return chatModel;

        } catch (Exception e) {
            log.error("Anthropic 모델 생성 실패: {}", modelId, e);
            throw new RuntimeException("Failed to create Anthropic model: " + modelId, e);
        }
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType);
    }

    @Override
    public boolean supportsModel(String modelId) {
        
        ModelProviderProperties.AnthropicConfig anthropicConfig = modelProviderProperties.getAnthropic();
        if (anthropicConfig != null && anthropicConfig.getModels() != null &&
            anthropicConfig.getModels().containsKey(modelId)) {
            return true;
        }

        
        return modelCache.containsKey(modelId);
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        try {
            if (apiKey == null || apiKey.isEmpty()) {
                return HealthStatus.unhealthy("API key not configured");
            }

            if (restTemplate == null || baseUrl == null) {
                return HealthStatus.unhealthy("Anthropic not initialized");
            }

            
            String messagesUrl = baseUrl + "/v1/messages";

            HttpHeaders headers = new HttpHeaders();
            headers.set("x-api-key", apiKey);
            headers.set("anthropic-version", "2023-06-01");
            headers.set("content-type", "application/json");

            
            String testModel = "claude-3-haiku-20240307"; 
            ModelProviderProperties.AnthropicConfig anthropicConfig = modelProviderProperties.getAnthropic();
            if (anthropicConfig != null && anthropicConfig.getModels() != null && !anthropicConfig.getModels().isEmpty()) {
                
                ModelProviderProperties.ModelSpec firstSpec = anthropicConfig.getModels().values().iterator().next();
                if (firstSpec != null && firstSpec.getVersion() != null) {
                    testModel = firstSpec.getVersion();
                }
            }

            
            String testPayload = "{"
                + "\"model\": \"" + testModel + "\","
                + "\"max_tokens\": 1,"
                + "\"messages\": [{\"role\": \"user\", \"content\": \"test\"}]"
                + "}";

            HttpEntity<String> entity = new HttpEntity<>(testPayload, headers);

            try {
                ResponseEntity<Map> response = restTemplate.exchange(
                    messagesUrl, HttpMethod.POST, entity, Map.class);

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
        log.info("AnthropicModelProvider 초기화 시작");

        try {
            
            ModelProviderProperties.AnthropicConfig anthropicConfig = modelProviderProperties.getAnthropic();
            if (anthropicConfig != null && anthropicConfig.isEnabled()) {
                this.baseUrl = anthropicConfig.getBaseUrl();
            } else {
                log.warn("Anthropic가 비활성화되어 있거나 설정이 없습니다");
                ready = false;
                return;
            }

            if (apiKey == null || apiKey.isEmpty()) {
                log.warn("Anthropic API 키가 설정되지 않았지만 계속 진행합니다");
                
            }

            
            this.restTemplate = new RestTemplate();

            ready = true; 
            log.info("AnthropicModelProvider 초기화 완료 - baseUrl: {}, API 키 설정: {}",
                     baseUrl, apiKey != null && !apiKey.isEmpty());
        } catch (Exception e) {
            log.error("AnthropicModelProvider 초기화 실패", e);
            ready = false;
        }
    }

    @Override
    public void shutdown() {
        log.info("AnthropicModelProvider 종료");
        modelInstances.clear();
        modelCache.clear();
        ready = false;
    }

    @Override
    public boolean isReady() {
        return ready && apiKey != null && !apiKey.isEmpty();
    }

    @Override
    public void refreshModels() {
        log.info("Anthropic 모델 목록 새로고침");
        
    }

    @Override
    public int getPriority() {
        return 20; 
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("cachedModels", modelCache.size());
        metrics.put("activeInstances", modelInstances.size());
        metrics.put("ready", ready);
        metrics.put("apiKeyConfigured", apiKey != null && !apiKey.isEmpty());
        return metrics;
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
        }

        ModelDescriptor.ThroughputLevel throughput = ModelDescriptor.ThroughputLevel.valueOf(
            spec.getPerformance().getThroughputLevel());

        return ModelDescriptor.builder()
            .modelId(modelId)
            .displayName(spec.getDisplayName())
            .provider(getProviderName())
            .version(spec.getVersion())
            .modelSize(spec.getModelSize() != null ? spec.getModelSize() : "N/A")
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
                .topK(spec.getOptions().getTopK())
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

    
    private AnthropicApi getAnthropicApi() {
        if (anthropicApi == null) {
            throw new IllegalStateException("AnthropicApi not available. Please check Anthropic configuration.");
        }
        return anthropicApi;
    }

}