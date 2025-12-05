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

/**
 * vLLM 모델 제공자 구현
 *
 * vLLM은 OpenAI 호환 API를 제공하므로 Spring AI의 OpenAiChatModel을 재사용합니다.
 * PagedAttention 기반의 고처리량 추론 엔진으로 Ollama 대비 약 10배의 처리량을 제공합니다.
 *
 * 특징:
 * - OpenAI 호환 API (/v1/chat/completions, /v1/models 등)
 * - PagedAttention: KV 캐시 메모리 낭비 60-80% → 4% 미만으로 감소
 * - Continuous Batching: 동적 배치로 GPU 활용률 극대화
 * - 로컬 실행: API 키 불필요, 무료 사용
 *
 * Zero Trust 아키텍처에서의 역할:
 * - 초당 수백~수천 건의 보안 이벤트 분석 처리
 * - Ollama 대비 10배 처리량으로 지연 시간 최소화
 * - 로컬 실행으로 데이터 보안 유지
 *
 * @since 3.0.0
 */
@Slf4j
public class VLLMModelProvider implements ModelProvider {

    // baseUrl은 ModelProviderProperties.VLLMConfig에서 가져옴
    private String baseUrl;

    @Autowired
    private ModelProviderProperties modelProviderProperties;

    private RestTemplate restTemplate;
    private OpenAiApi vllmApi;
    private final Map<String, ModelDescriptor> modelCache = new ConcurrentHashMap<>();
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    private final Map<String, VLLMModelInfo> discoveredModels = new ConcurrentHashMap<>();
    private boolean ready = false;

    /**
     * vLLM API 응답 모델 (OpenAI 호환)
     */
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

        // 설정 파일에서 정의된 모델들
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

        // 동적으로 발견된 모델들
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

        // 설정 파일에서 찾기
        ModelProviderProperties.VLLMConfig vllmConfig = modelProviderProperties.getVllm();
        if (vllmConfig != null && vllmConfig.getModels() != null) {
            ModelProviderProperties.ModelSpec spec = vllmConfig.getModels().get(modelId);
            if (spec != null) {
                ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                modelCache.put(modelId, descriptor);
                return descriptor;
            }
        }

        // 동적으로 발견된 모델에서 찾기
        VLLMModelInfo info = discoveredModels.get(modelId);
        if (info != null) {
            ModelDescriptor descriptor = createModelDescriptorFromDiscovery(modelId, info);
            modelCache.put(modelId, descriptor);
            return descriptor;
        }

        // vLLM API에서 직접 조회 시도
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

        // 캐시 확인
        if (modelInstances.containsKey(modelId)) {
            return modelInstances.get(modelId);
        }

        try {
            // OpenAiChatOptions 생성 (vLLM은 OpenAI 호환)
            OpenAiChatOptions.Builder optionsBuilder = OpenAiChatOptions.builder()
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
            }

            // 최대 토큰 설정
            if (descriptor.getCapabilities() != null) {
                optionsBuilder.maxTokens(descriptor.getCapabilities().getMaxOutputTokens());
            }

            // 추가 설정 적용
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

            // API 사용 가능 여부 체크
            if (!isReady()) {
                throw new ModelSelectionException("vLLM server not available at " + baseUrl, modelId);
            }

            // vLLM용 OpenAiApi 생성 (baseUrl만 다름, API 키 불필요)
            OpenAiApi api = getVLLMApi();

            // OpenAiChatModel 생성 (vLLM은 OpenAI 호환 API)
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
        // 설정 파일 확인
        ModelProviderProperties.VLLMConfig vllmConfig = modelProviderProperties.getVllm();
        if (vllmConfig != null && vllmConfig.getModels() != null &&
            vllmConfig.getModels().containsKey(modelId)) {
            return true;
        }

        // 캐시 확인
        if (modelCache.containsKey(modelId)) {
            return true;
        }

        // 동적으로 발견된 모델 확인
        return discoveredModels.containsKey(modelId);
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        try {
            if (restTemplate == null || baseUrl == null) {
                return HealthStatus.unhealthy("vLLM not initialized");
            }

            // vLLM 헬스 체크 - /health 엔드포인트 또는 /v1/models
            String healthUrl = baseUrl + "/health";

            try {
                ResponseEntity<String> response = restTemplate.getForEntity(healthUrl, String.class);

                if (response.getStatusCode() == HttpStatus.OK) {
                    Map<String, Object> details = new HashMap<>();
                    details.put("status", "healthy");
                    details.put("baseUrl", baseUrl);
                    details.put("provider", "vLLM");
                    details.put("feature", "PagedAttention high-throughput inference");

                    // 특정 모델 사용 가능 여부 확인
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
                // /health가 없으면 /v1/models로 폴백
                return checkHealthViaModels(modelId);
            }
        } catch (Exception e) {
            return HealthStatus.unhealthy("Health check failed: " + e.getMessage());
        }
    }

    /**
     * /v1/models 엔드포인트로 헬스 체크 (폴백)
     */
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
            // 설정에서 baseUrl 가져오기
            ModelProviderProperties.VLLMConfig vllmConfig = modelProviderProperties.getVllm();
            if (vllmConfig != null && vllmConfig.isEnabled()) {
                this.baseUrl = vllmConfig.getBaseUrl();
            } else {
                log.warn("vLLM이 비활성화되어 있거나 설정이 없습니다");
                ready = false;
                return;
            }

            // RestTemplate 초기화
            this.restTemplate = new RestTemplate();

            // vLLM API 초기화 (OpenAI 호환, API 키 불필요)
            this.vllmApi = OpenAiApi.builder()
                .baseUrl(baseUrl)
                .apiKey("dummy-key-for-local-vllm")  // vLLM은 API 키 불필요하지만 Spring AI가 요구
                .build();

            // 모델 목록 로드 시도
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
        // vLLM은 Ollama보다 높은 우선순위 (고처리량)
        // Ollama: 10, vLLM: 5 (낮을수록 높은 우선순위)
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

    /**
     * vLLM에서 실제 모델 목록 로드
     */
    private boolean loadModelsFromVLLM() {
        if (restTemplate == null || baseUrl == null) {
            log.warn("RestTemplate 또는 baseUrl이 설정되지 않아 모델 목록을 로드할 수 없습니다");
            return false;
        }

        try {
            // vLLM API를 통해 모델 목록 조회 (OpenAI 호환)
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

    /**
     * 동적으로 발견된 모델로부터 디스크립터 생성
     */
    private ModelDescriptor createModelDescriptorFromDiscovery(String modelId, VLLMModelInfo info) {
        // 모델 이름에서 tier 추정
        int tier = estimateTierFromModelId(modelId);

        // 설정에서 기본값 가져오기
        ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
            modelProviderProperties.getTierDefaults(tier);

        if (tierDefaults == null) {
            tierDefaults = new ModelProviderProperties.DefaultSpecs.TierDefaults();
            tierDefaults.setTimeoutMs(5000);
            tierDefaults.setTemperature(0.5);
            tierDefaults.setMaxTokens(4096);
            tierDefaults.setContextWindow(4096);
            tierDefaults.setPerformanceScore(90.0);  // vLLM은 고성능
            tierDefaults.setLatencyMs(50);  // vLLM은 저지연
            tierDefaults.setConcurrency(200);  // vLLM은 고처리량
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
                .toolCalling(true)  // vLLM은 대부분 도구 호출 지원
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
                .throughput(ModelDescriptor.ThroughputLevel.HIGH)  // vLLM은 항상 고처리량
                .concurrency(tierDefaults.getConcurrency())
                .recommendedTimeout(tierDefaults.getTimeoutMs())
                .performanceScore(tierDefaults.getPerformanceScore())
                .build())
            .cost(ModelDescriptor.CostProfile.builder()
                .costPerInputToken(0.0)  // 로컬 실행이므로 무료
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

    /**
     * 모델 ID로부터 Tier 추정
     */
    private int estimateTierFromModelId(String modelId) {
        if (modelId == null) return 2;

        String lower = modelId.toLowerCase();

        // 대형 모델 (70B+)
        if (lower.contains("70b") || lower.contains("72b") || lower.contains("llama-3.1-70b")) {
            return 3;
        }

        // 중형 모델 (7B-30B)
        if (lower.contains("7b") || lower.contains("8b") || lower.contains("13b") ||
            lower.contains("llama-3") || lower.contains("mistral")) {
            return 2;
        }

        // 소형 모델
        if (lower.contains("3b") || lower.contains("1b") || lower.contains("tiny") || lower.contains("small")) {
            return 1;
        }

        return 2;  // 기본값
    }

    /**
     * vLLM API 인스턴스 반환
     */
    private OpenAiApi getVLLMApi() {
        if (vllmApi == null) {
            // 지연 초기화
            this.vllmApi = OpenAiApi.builder()
                .baseUrl(baseUrl)
                .apiKey("dummy-key-for-local-vllm")
                .build();
        }
        return vllmApi;
    }
}
