package io.contexa.contexacore.std.llm.model.provider;

import io.contexa.contexacore.config.ModelProviderProperties;
import io.contexa.contexacore.std.llm.model.ModelDescriptor;
import io.contexa.contexacore.std.llm.model.ModelProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ModelProvider의 공통 기능을 제공하는 추상 클래스.
 * Template Method 패턴을 사용하여 공통 로직을 캡슐화하고,
 * 프로바이더별 차이점은 하위 클래스에서 구현한다.
 */
@Slf4j
public abstract class BaseModelProvider implements ModelProvider {

    @Autowired
    protected ModelProviderProperties modelProviderProperties;

    protected String baseUrl;
    protected RestTemplate restTemplate;
    protected final Map<String, ModelDescriptor> modelCache = new ConcurrentHashMap<>();
    protected final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();
    protected boolean ready = false;

    // ========== 추상 메서드 (하위 클래스에서 구현) ==========

    @Override
    public abstract String getProviderName();

    @Override
    public abstract String getDescription();

    @Override
    public abstract ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config);

    @Override
    public abstract HealthStatus checkHealth(String modelId);

    @Override
    public abstract boolean supportsModelType(String modelType);

    @Override
    public abstract int getPriority();

    /**
     * 프로바이더별 설정 객체 반환 (Ollama, Anthropic, OpenAI Config)
     */
    protected abstract ModelProviderProperties.BaseProviderConfig getProviderConfig();

    /**
     * 프로바이더별 초기화 로직 (Template Method hook)
     */
    protected abstract void doInitialize(Map<String, Object> config);

    /**
     * 프로바이더별 추가 메트릭스 (Optional)
     */
    protected Map<String, Object> getAdditionalMetrics() {
        return Collections.emptyMap();
    }

    // ========== 공통 구현 ==========

    @Override
    public void initialize(Map<String, Object> config) {
        try {
            var providerConfig = getProviderConfig();
            if (providerConfig != null && providerConfig.isEnabled()) {
                this.baseUrl = providerConfig.getBaseUrl();
            } else {
                log.warn("{} is disabled or not configured", getProviderName());
                ready = false;
                return;
            }

            this.restTemplate = new RestTemplate();
            doInitialize(config);
            ready = true;
        } catch (Exception e) {
            log.error("{}ModelProvider initialization failed", getProviderName(), e);
            ready = false;
        }
    }

    @Override
    public void shutdown() {
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
        // 기본 구현: 아무 작업 안함. 필요시 하위 클래스에서 override
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("cachedModels", modelCache.size());
        metrics.put("activeInstances", modelInstances.size());
        metrics.put("ready", ready);
        metrics.put("baseUrl", baseUrl);
        metrics.putAll(getAdditionalMetrics());
        return metrics;
    }

    @Override
    public List<ModelDescriptor> getAvailableModels() {
        List<ModelDescriptor> models = new ArrayList<>();

        var providerConfig = getProviderConfig();
        if (providerConfig != null && providerConfig.getModels() != null) {
            for (Map.Entry<String, ModelProviderProperties.ModelSpec> entry :
                    providerConfig.getModels().entrySet()) {
                String modelId = entry.getKey();
                ModelProviderProperties.ModelSpec spec = entry.getValue();

                if (!modelCache.containsKey(modelId)) {
                    ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                    modelCache.put(modelId, descriptor);
                }
                models.add(modelCache.get(modelId));
            }
        }

        models.addAll(getDiscoveredModels());
        return models;
    }

    /**
     * 동적 발견된 모델 목록 (Optional, 하위 클래스에서 override)
     */
    protected List<ModelDescriptor> getDiscoveredModels() {
        return Collections.emptyList();
    }

    @Override
    public ModelDescriptor getModelDescriptor(String modelId) {
        if (modelCache.containsKey(modelId)) {
            return modelCache.get(modelId);
        }

        var providerConfig = getProviderConfig();
        if (providerConfig != null && providerConfig.getModels() != null) {
            ModelProviderProperties.ModelSpec spec = providerConfig.getModels().get(modelId);
            if (spec != null) {
                ModelDescriptor descriptor = createModelDescriptorFromSpec(modelId, spec);
                modelCache.put(modelId, descriptor);
                return descriptor;
            }
        }

        return findDiscoveredModel(modelId);
    }

    /**
     * 동적 발견된 모델에서 검색 (Optional, 하위 클래스에서 override)
     */
    protected ModelDescriptor findDiscoveredModel(String modelId) {
        return null;
    }

    @Override
    public boolean supportsModel(String modelId) {
        var providerConfig = getProviderConfig();
        if (providerConfig != null && providerConfig.getModels() != null &&
            providerConfig.getModels().containsKey(modelId)) {
            return true;
        }
        return modelCache.containsKey(modelId);
    }

    /**
     * 캐시된 ChatModel 인스턴스 조회
     */
    protected ChatModel getCachedModel(String modelId) {
        return modelInstances.get(modelId);
    }

    /**
     * ChatModel 인스턴스 캐시에 저장
     */
    protected void cacheModel(String modelId, ChatModel model) {
        modelInstances.put(modelId, model);
    }

    /**
     * 캐시에 모델이 있는지 확인
     */
    protected boolean hasCachedModel(String modelId) {
        return modelInstances.containsKey(modelId);
    }

    /**
     * ModelSpec에서 ModelDescriptor 생성 (공통 로직)
     */
    protected ModelDescriptor createModelDescriptorFromSpec(
            String modelId, ModelProviderProperties.ModelSpec spec) {

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
                .repetitionPenalty(spec.getOptions().getRepetitionPenalty())
                .build())
            .status(getModelStatus())
            .metadata(spec.getMetadata() != null ? spec.getMetadata() : getDefaultMetadata())
            .build();
    }

    /**
     * 모델 상태 반환 (하위 클래스에서 override 가능)
     */
    protected ModelDescriptor.ModelStatus getModelStatus() {
        return ModelDescriptor.ModelStatus.AVAILABLE;
    }

    /**
     * 기본 메타데이터 반환 (하위 클래스에서 override)
     */
    protected Map<String, Object> getDefaultMetadata() {
        return Map.of();
    }
}
