package io.contexa.contexacore.std.llm.model.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.config.ModelProviderProperties;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import io.contexa.contexacore.std.llm.model.ModelProvider;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.ai.ollama.api.OllamaOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Ollama 모델 제공자 구현
 *
 * 로컬 Ollama 서버와 통신하여 모델을 관리하고 제공합니다.
 */
@Slf4j
@Component
public class OllamaModelProvider implements ModelProvider {

    @Autowired
    private ModelProviderProperties modelProviderProperties;

    @Autowired(required = false)
    private OllamaChatModel defaultOllamaChatModel;

    @Autowired(required = false)
    private OllamaApi ollamaApi;

    private String baseUrl;
    private RestTemplate restTemplate;
    private ObjectMapper objectMapper;
    private final Map<String, ModelDescriptor> modelCache = new ConcurrentHashMap<>();
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    private final Map<String, OllamaModelDetails> discoveredModels = new ConcurrentHashMap<>();
    private boolean ready = false;

    /**
     * Ollama API 응답 모델
     */
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

    @Override
    public String getProviderName() {
        return "ollama";
    }

    @Override
    public String getDescription() {
        return "Local Ollama model provider for on-premise LLM deployment";
    }

    @Override
    public List<ModelDescriptor> getAvailableModels() {
        List<ModelDescriptor> models = new ArrayList<>();

        // 1. 설정 파일에서 정의된 모델들
        ModelProviderProperties.OllamaConfig ollamaConfig = modelProviderProperties.getOllama();
        if (ollamaConfig != null && ollamaConfig.getModels() != null) {
            for (Map.Entry<String, ModelProviderProperties.ModelSpec> entry :
                    ollamaConfig.getModels().entrySet()) {
                String modelId = entry.getKey();
                ModelProviderProperties.ModelSpec spec = entry.getValue();

                if (!modelCache.containsKey(modelId)) {
                    ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                    modelCache.put(modelId, descriptor);
                }
                models.add(modelCache.get(modelId));
            }
        }

        // 2. 동적으로 발견된 모델들 (Ollama API에서 조회)
        for (Map.Entry<String, OllamaModelDetails> entry : discoveredModels.entrySet()) {
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

        // 1. 설정 파일에서 찾기
        ModelProviderProperties.OllamaConfig ollamaConfig = modelProviderProperties.getOllama();
        if (ollamaConfig != null && ollamaConfig.getModels() != null) {
            ModelProviderProperties.ModelSpec spec = ollamaConfig.getModels().get(modelId);
            if (spec != null) {
                ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                modelCache.put(modelId, descriptor);
                return descriptor;
            }
        }

        // 2. 동적으로 발견된 모델에서 찾기
        OllamaModelDetails details = discoveredModels.get(modelId);
        if (details != null) {
            ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, details);
            modelCache.put(modelId, descriptor);
            return descriptor;
        }

        // 3. Ollama API에서 직접 조회 시도
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
    public ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config) {
        String modelId = descriptor.getModelId();

        // 캐시 확인
        if (modelInstances.containsKey(modelId)) {
            return modelInstances.get(modelId);
        }

        try {
            // OllamaOptions 생성
            OllamaOptions.Builder optionsBuilder = OllamaOptions.builder()
                .model(modelId);

            // 설정 적용
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

            // 추가 설정 적용
            if (config != null) {
                if (config.containsKey("temperature")) {
                    optionsBuilder.temperature((Double) config.get("temperature"));
                }
                if (config.containsKey("maxTokens")) {
                    optionsBuilder.numPredict((Integer) config.get("maxTokens"));
                }
            }

            OllamaOptions ollamaOptions = optionsBuilder.build();

            // OllamaChatModel 생성
            OllamaChatModel chatModel = OllamaChatModel.builder()
                .ollamaApi(getOllamaApi())
                .defaultOptions(ollamaOptions)
                .build();

            modelInstances.put(modelId, chatModel);
            log.info("Ollama 모델 생성 완료: {}", modelId);

            return chatModel;

        } catch (Exception e) {
            log.error("Ollama 모델 생성 실패: {}", modelId, e);
            throw new RuntimeException("Failed to create Ollama model: " + modelId, e);
        }
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType) ||
               ModelType.EMBEDDING.equals(modelType);
    }

    @Override
    public boolean supportsModel(String modelId) {
        // 설정 파일에서 확인
        ModelProviderProperties.OllamaConfig ollamaConfig = modelProviderProperties.getOllama();
        if (ollamaConfig != null && ollamaConfig.getModels() != null &&
            ollamaConfig.getModels().containsKey(modelId)) {
            return true;
        }

        // 캐시에서 확인
        return modelCache.containsKey(modelId) ||
               discoveredModels.containsKey(modelId);
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        try {
            if (restTemplate == null || baseUrl == null) {
                return HealthStatus.unhealthy("Ollama not initialized");
            }

            // Ollama API 헬스 체크 - /api/version 엔드포인트 호출
            String versionUrl = baseUrl + "/api/version";
            ResponseEntity<Map> response = restTemplate.getForEntity(versionUrl, Map.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                Map<String, Object> details = new HashMap<>();
                details.put("status", "healthy");
                details.put("baseUrl", baseUrl);
                if (response.getBody() != null) {
                    details.put("version", response.getBody().get("version"));
                }

                // 특정 모델이 지정된 경우 해당 모델 존재 여부 확인
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

    @Override
    public void initialize(Map<String, Object> config) {
        log.info("OllamaModelProvider 초기화 시작");

        try {
            // 설정에서 baseUrl 가져오기
            ModelProviderProperties.OllamaConfig ollamaConfig = modelProviderProperties.getOllama();
            if (ollamaConfig != null && ollamaConfig.isEnabled()) {
                this.baseUrl = ollamaConfig.getBaseUrl();
            } else {
                log.warn("Ollama가 비활성화되어 있거나 설정이 없습니다");
                ready = false;
                return;
            }

            // RestTemplate 및 ObjectMapper 초기화
            this.restTemplate = new RestTemplate();
            this.objectMapper = new ObjectMapper();

            // 모델 목록 로드 시도
            boolean modelsLoaded = loadModelsFromOllama();

            // Ollama 연결 실패해도 설정 파일의 모델은 사용 가능하도록
            if (!modelsLoaded) {
                log.warn("Ollama 서버에서 모델을 로드하지 못했지만, 설정 파일의 모델 정의를 사용합니다");
                // 설정 파일에 정의된 모델만 사용 가능
            }

            ready = true; // 설정 파일에 모델이 정의되어 있으면 ready
            log.info("OllamaModelProvider 초기화 완료 - baseUrl: {}, 모델 로드: {}", baseUrl, modelsLoaded);
        } catch (Exception e) {
            log.error("OllamaModelProvider 초기화 실패", e);
            ready = false;
        }
    }

    @Override
    public void shutdown() {
        log.info("OllamaModelProvider 종료");
        modelInstances.clear();
        modelCache.clear();
        ready = false;
    }

    @Override
    public boolean isReady() {
        return ready;
    }

    @Override
    public void refreshModels() {
        log.info("Ollama 모델 목록 새로고침");
        loadModelsFromOllama();
    }

    @Override
    public int getPriority() {
        return 10; // 로컬 모델이므로 높은 우선순위
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("cachedModels", modelCache.size());
        metrics.put("activeInstances", modelInstances.size());
        metrics.put("ready", ready);
        metrics.put("baseUrl", baseUrl);
        return metrics;
    }

    /**
     * Ollama에서 실제 모델 목록 로드
     */
    private boolean loadModelsFromOllama() {
        if (restTemplate == null || baseUrl == null) {
            log.warn("RestTemplate 또는 baseUrl이 설정되지 않아 모델 목록을 로드할 수 없습니다");
            return false;
        }

        try {
            // Ollama API를 통해 실제 설치된 모델 목록 조회
            String tagsUrl = baseUrl + "/api/tags";
            log.debug("Ollama API 호출: {}", tagsUrl);

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
                        log.info("Ollama 모델 발견: {} (size: {})",
                                modelName, details.getParameter_size());
                    }

                    log.info("Ollama에서 {} 개의 모델을 발견했습니다", discoveredModels.size());
                    return true;
                }
            } else {
                log.warn("Ollama API 응답이 비정상입니다: {}", response.getStatusCode());
            }
        } catch (RestClientException e) {
            log.warn("Ollama 서버 연결 실패 (정상적인 경우일 수 있음): {}", e.getMessage());
        } catch (Exception e) {
            log.error("Ollama 모델 목록 로드 중 오류 발생", e);
        }
        return false;
    }

    /**
     * 설정 스펙으로부터 모델 디스크립터 생성
     */
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
                .topK(spec.getOptions().getTopK())
                .repetitionPenalty(spec.getOptions().getRepetitionPenalty())
                .build())
            .status(ModelDescriptor.ModelStatus.AVAILABLE)
            .metadata(spec.getMetadata() != null ? spec.getMetadata() : Map.of(
                "local", true,
                "requiresGPU", !modelId.contains("tiny")
            ))
            .build();
    }

    /**
     * 동적으로 발견된 모델로부터 디스크립터 생성
     */
    private ModelDescriptor createModelDescriptorFromDiscovery(String modelId, OllamaModelDetails details) {
        // 모델 크기에서 tier 추정
        int tier = estimateTierFromSize(details.getParameter_size());

        // 설정에서 기본값 가져오기 (null일 경우 기본값 생성)
        ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
            modelProviderProperties.getTierDefaults(tier);

        if (tierDefaults == null) {
            // 기본값 생성
            tierDefaults = new ModelProviderProperties.DefaultSpecs.TierDefaults();
            tierDefaults.setTimeoutMs(5000);
            tierDefaults.setTemperature(0.5);
            tierDefaults.setMaxTokens(4096);
            tierDefaults.setContextWindow(4096);
            tierDefaults.setPerformanceScore(75.0);
            tierDefaults.setLatencyMs(1000);
            tierDefaults.setConcurrency(50);
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
                .costPerInputToken(0.0)
                .costPerOutputToken(0.0)
                .costEfficiency(100.0)
                .build())
            .options(ModelDescriptor.ModelOptions.builder()
                .temperature(tierDefaults.getTemperature())
                .topP(0.9)
                .repetitionPenalty(1.0)
                .build())
            .status(ModelDescriptor.ModelStatus.AVAILABLE)
            .metadata(Map.of(
                "local", true,
                "dynamicallyDiscovered", true,
                "requiresGPU", !modelId.contains("tiny")
            ))
            .build();
    }

    /**
     * 모델 크기로부터 Tier 추정
     */
    private int estimateTierFromSize(String parameterSize) {
        if (parameterSize == null || parameterSize.equals("unknown")) {
            return 2; // 기본값
        }

        // 파라미터 크기에서 숫자 추출
        String sizeStr = parameterSize.toLowerCase()
            .replace("b", "")
            .replace("billion", "")
            .replace("million", "")
            .replace("m", "")
            .trim();

        try {
            double size = Double.parseDouble(sizeStr);

            // million 단위인 경우 billion으로 변환
            if (parameterSize.toLowerCase().contains("m")) {
                size = size / 1000.0;
            }

            // 크기에 따른 Tier 분류
            if (size < 5) {
                return 1; // 소형 모델 (< 5B)
            } else if (size < 20) {
                return 2; // 중형 모델 (5B - 20B)
            } else {
                return 3; // 대형 모델 (> 20B)
            }
        } catch (NumberFormatException e) {
            log.debug("파라미터 크기 파싱 실패: {}", parameterSize);
            return 2; // 기본값
        }
    }

    /**
     * OllamaApi 인스턴스 반환
     */
    private OllamaApi getOllamaApi() {
        if (ollamaApi == null) {
            throw new IllegalStateException("OllamaApi not available. Please check Ollama configuration.");
        }
        return ollamaApi;
    }

}