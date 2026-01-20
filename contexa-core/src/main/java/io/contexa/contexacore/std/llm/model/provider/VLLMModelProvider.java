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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
public class VLLMModelProvider implements ModelProvider {

    
    private String baseUrl;

    @Autowired
    private ModelProviderProperties modelProviderProperties;

    private RestTemplate restTemplate;
    private OpenAiApi vllmApi;
    private final Map<String, ModelDescriptor> modelCache = new ConcurrentHashMap<>();
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    private final Map<String, VLLMModelInfo> discoveredModels = new ConcurrentHashMap<>();
    private boolean ready = false;

    
    @Data
    public static class VLLMModelsResponse {
        private List<VLLMModelInfo> data;
        private String object;
    }

    @Data
    public static class VLLMModelInfo {
        private String id;
        private String object;
        private Long created;
        private String owned_by;
        private String root;
        private String parent;
    }

    @Override
    public String getProviderName() {
        return "vllm";
    }

    @Override
    public String getDescription() {
        return "vLLM high-throughput inference engine with PagedAttention for local LLM deployment";
    }

    @Override
    public List<ModelDescriptor> getAvailableModels() {
        List<ModelDescriptor> models = new ArrayList<>();

        
        ModelProviderProperties.VLLMConfig vllmConfig = modelProviderProperties.getVllm();
        if (vllmConfig != null && vllmConfig.getModels() != null) {
            for (Map.Entry<String, ModelProviderProperties.ModelSpec> entry :
                    vllmConfig.getModels().entrySet()) {
                String modelId = entry.getKey();
                ModelProviderProperties.ModelSpec spec = entry.getValue();

                if (!modelCache.containsKey(modelId)) {
                    ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                    modelCache.put(modelId, descriptor);
                }
                models.add(modelCache.get(modelId));
            }
        }

        
        for (Map.Entry<String, VLLMModelInfo> entry : discoveredModels.entrySet()) {
            String modelId = entry.getKey();
            if (!modelCache.containsKey(modelId)) {
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

        
        ModelProviderProperties.VLLMConfig vllmConfig = modelProviderProperties.getVllm();
        if (vllmConfig != null && vllmConfig.getModels() != null) {
            ModelProviderProperties.ModelSpec spec = vllmConfig.getModels().get(modelId);
            if (spec != null) {
                ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                modelCache.put(modelId, descriptor);
                return descriptor;
            }
        }

        
        VLLMModelInfo info = discoveredModels.get(modelId);
        if (info != null) {
            ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, info);
            modelCache.put(modelId, descriptor);
            return descriptor;
        }

        
        loadModelsFromVLLM();
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
            }

            OpenAiChatOptions vllmOptions = optionsBuilder.build();

            
            if (!isReady()) {
                throw new ModelSelectionException("vLLM server not available at " + baseUrl, modelId);
            }

            
            OpenAiApi api = getVLLMApi();

            
            OpenAiChatModel chatModel = OpenAiChatModel.builder()
                .openAiApi(api)
                .defaultOptions(vllmOptions)
                .build();

            modelInstances.put(modelId, chatModel);
            log.info("vLLM 모델 생성 완료: {} (baseUrl: {})", modelId, baseUrl);

            return chatModel;

        } catch (Exception e) {
            log.error("vLLM 모델 생성 실패: {}", modelId, e);
            throw new RuntimeException("Failed to create vLLM model: " + modelId, e);
        }
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType) ||
               ModelType.EMBEDDING.equals(modelType);
    }

    @Override
    public boolean supportsModel(String modelId) {
        
        ModelProviderProperties.VLLMConfig vllmConfig = modelProviderProperties.getVllm();
        if (vllmConfig != null && vllmConfig.getModels() != null &&
            vllmConfig.getModels().containsKey(modelId)) {
            return true;
        }

        
        if (modelCache.containsKey(modelId)) {
            return true;
        }

        
        return discoveredModels.containsKey(modelId);
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        try {
            if (restTemplate == null || baseUrl == null) {
                return HealthStatus.unhealthy("vLLM not initialized");
            }

            
            String healthUrl = baseUrl + "/health";

            try {
                ResponseEntity<String> response = restTemplate.getForEntity(healthUrl, String.class);

                if (response.getStatusCode() == HttpStatus.OK) {
                    Map<String, Object> details = new HashMap<>();
                    details.put("status", "healthy");
                    details.put("baseUrl", baseUrl);
                    details.put("provider", "vLLM");
                    details.put("feature", "PagedAttention high-throughput inference");

                    
                    if (modelId != null && !modelId.isEmpty()) {
                        boolean modelExists = discoveredModels.containsKey(modelId) ||
                                            (modelProviderProperties.getVllm() != null &&
                                             modelProviderProperties.getVllm().getModels().containsKey(modelId));
                        details.put("modelAvailable", modelExists);
                    }

                    return new HealthStatus(true, "Healthy", 0, details);
                }

                return HealthStatus.unhealthy("vLLM API returned status: " + response.getStatusCode());

            } catch (RestClientException e) {
                
                return checkHealthViaModels(modelId);
            }
        } catch (Exception e) {
            return HealthStatus.unhealthy("Health check failed: " + e.getMessage());
        }
    }

    
    private HealthStatus checkHealthViaModels(String modelId) {
        try {
            String modelsUrl = baseUrl + "/v1/models";
            ResponseEntity<VLLMModelsResponse> response = restTemplate.getForEntity(
                modelsUrl, VLLMModelsResponse.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> details = new HashMap<>();
                details.put("status", "healthy");
                details.put("baseUrl", baseUrl);
                details.put("provider", "vLLM");

                if (response.getBody() != null && response.getBody().getData() != null) {
                    details.put("availableModels", response.getBody().getData().size());
                }

                return new HealthStatus(true, "Healthy", 0, details);
            }

            return HealthStatus.unhealthy("vLLM API returned status: " + response.getStatusCode());
        } catch (RestClientException e) {
            return HealthStatus.unhealthy("Cannot connect to vLLM: " + e.getMessage());
        }
    }

    @Override
    public void initialize(Map<String, Object> config) {
        log.info("VLLMModelProvider 초기화 시작");

        try {
            
            ModelProviderProperties.VLLMConfig vllmConfig = modelProviderProperties.getVllm();
            if (vllmConfig != null && vllmConfig.isEnabled()) {
                this.baseUrl = vllmConfig.getBaseUrl();
            } else {
                log.warn("vLLM이 비활성화되어 있거나 설정이 없습니다");
                ready = false;
                return;
            }

            
            this.restTemplate = new RestTemplate();

            
            this.vllmApi = OpenAiApi.builder()
                .baseUrl(baseUrl)
                .apiKey("dummy-key-for-local-vllm")  
                .build();

            
            boolean modelsLoaded = loadModelsFromVLLM();

            if (!modelsLoaded) {
                log.warn("vLLM 서버에서 모델을 로드하지 못했지만, 설정 파일의 모델 정의를 사용합니다");
            }

            ready = true;
            log.info("VLLMModelProvider 초기화 완료 - baseUrl: {}, 모델 로드: {}", baseUrl, modelsLoaded);
        } catch (Exception e) {
            log.error("VLLMModelProvider 초기화 실패", e);
            ready = false;
        }
    }

    @Override
    public void shutdown() {
        log.info("VLLMModelProvider 종료");
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
        log.info("vLLM 모델 목록 새로고침");
        loadModelsFromVLLM();
    }

    @Override
    public int getPriority() {
        
        
        return 5;
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("cachedModels", modelCache.size());
        metrics.put("activeInstances", modelInstances.size());
        metrics.put("discoveredModels", discoveredModels.size());
        metrics.put("ready", ready);
        metrics.put("baseUrl", baseUrl);
        metrics.put("provider", "vLLM");
        metrics.put("feature", "PagedAttention");
        metrics.put("throughputMultiplier", "10x vs Ollama");
        return metrics;
    }

    
    private boolean loadModelsFromVLLM() {
        if (restTemplate == null || baseUrl == null) {
            log.warn("RestTemplate 또는 baseUrl이 설정되지 않아 모델 목록을 로드할 수 없습니다");
            return false;
        }

        try {
            
            String modelsUrl = baseUrl + "/v1/models";
            log.debug("vLLM API 호출: {}", modelsUrl);

            ResponseEntity<VLLMModelsResponse> response = restTemplate.getForEntity(
                modelsUrl, VLLMModelsResponse.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                VLLMModelsResponse modelsResponse = response.getBody();

                if (modelsResponse.getData() != null) {
                    discoveredModels.clear();

                    for (VLLMModelInfo model : modelsResponse.getData()) {
                        String modelId = model.getId();
                        discoveredModels.put(modelId, model);
                        log.info("vLLM 모델 발견: {}", modelId);
                    }

                    log.info("vLLM에서 {} 개의 모델을 발견했습니다", discoveredModels.size());
                    return true;
                }
            } else {
                log.warn("vLLM API 응답이 비정상입니다: {}", response.getStatusCode());
            }
        } catch (RestClientException e) {
            log.warn("vLLM 서버 연결 실패 (서버가 실행 중인지 확인): {}", e.getMessage());
        } catch (Exception e) {
            log.error("vLLM 모델 목록 로드 중 오류 발생", e);
        }
        return false;
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
            .status(ModelDescriptor.ModelStatus.AVAILABLE)
            .metadata(spec.getMetadata() != null ? spec.getMetadata() : Map.of(
                "local", true,
                "highThroughput", true,
                "pagedAttention", true,
                "throughputMultiplier", 10
            ))
            .build();
    }

    
    private ModelDescriptor createModelDescriptorFromDiscovery(String modelId, VLLMModelInfo info) {
        
        int tier = estimateTierFromModelId(modelId);

        
        ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
            modelProviderProperties.getTierDefaults(tier);

        if (tierDefaults == null) {
            tierDefaults = new ModelProviderProperties.DefaultSpecs.TierDefaults();
            tierDefaults.setTimeoutMs(5000);
            tierDefaults.setTemperature(0.5);
            tierDefaults.setMaxTokens(4096);
            tierDefaults.setContextWindow(4096);
            tierDefaults.setPerformanceScore(90.0);  
            tierDefaults.setLatencyMs(50);  
            tierDefaults.setConcurrency(200);  
        }

        return ModelDescriptor.builder()
            .modelId(modelId)
            .displayName(modelId)
            .provider(getProviderName())
            .version(modelId)
            .modelSize("N/A")
            .tier(tier)
            .capabilities(ModelDescriptor.ModelCapabilities.builder()
                .streaming(true)
                .toolCalling(true)  
                .functionCalling(true)
                .vision(modelId.toLowerCase().contains("vision"))
                .multiModal(false)
                .maxTokens(tierDefaults.getMaxTokens())
                .contextWindow(tierDefaults.getContextWindow())
                .supportsSystemMessage(true)
                .maxOutputTokens(4096)
                .build())
            .performance(ModelDescriptor.PerformanceProfile.builder()
                .latency(tierDefaults.getLatencyMs())
                .throughput(ModelDescriptor.ThroughputLevel.HIGH)  
                .concurrency(tierDefaults.getConcurrency())
                .recommendedTimeout(tierDefaults.getTimeoutMs())
                .performanceScore(tierDefaults.getPerformanceScore())
                .build())
            .cost(ModelDescriptor.CostProfile.builder()
                .costPerInputToken(0.0)  
                .costPerOutputToken(0.0)
                .costEfficiency(100.0)
                .build())
            .options(ModelDescriptor.ModelOptions.builder()
                .temperature(tierDefaults.getTemperature())
                .topP(0.9)
                .build())
            .status(ModelDescriptor.ModelStatus.AVAILABLE)
            .metadata(Map.of(
                "local", true,
                "dynamicallyDiscovered", true,
                "highThroughput", true,
                "pagedAttention", true,
                "throughputMultiplier", 10
            ))
            .build();
    }

    
    private int estimateTierFromModelId(String modelId) {
        if (modelId == null) return 2;

        String lower = modelId.toLowerCase();

        
        if (lower.contains("70b") || lower.contains("72b") || lower.contains("llama-3.1-70b")) {
            return 3;
        }

        
        if (lower.contains("7b") || lower.contains("8b") || lower.contains("13b") ||
            lower.contains("llama-3") || lower.contains("mistral")) {
            return 2;
        }

        
        if (lower.contains("3b") || lower.contains("1b") || lower.contains("tiny") || lower.contains("small")) {
            return 1;
        }

        return 2;  
    }

    
    private OpenAiApi getVLLMApi() {
        if (vllmApi == null) {
            
            this.vllmApi = OpenAiApi.builder()
                .baseUrl(baseUrl)
                .apiKey("dummy-key-for-local-vllm")
                .build();
        }
        return vllmApi;
    }
}
