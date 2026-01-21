package io.contexa.contexacore.std.llm.model;

import io.contexa.contexacore.config.ModelProviderProperties;
import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class DynamicModelRegistry {

    private final ApplicationContext applicationContext;
    private final TieredLLMProperties tieredLLMProperties;
    private final ModelProviderProperties modelProviderProperties;

    private final Map<String, ModelProvider> providers = new ConcurrentHashMap<>();

    private final Map<String, ModelDescriptor> modelDescriptors = new ConcurrentHashMap<>();

    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();

    private final Map<Integer, List<String>> tierModels = new ConcurrentHashMap<>();

    @PostConstruct
    public void initialize() {

        // 1. Spring AI가 자동 생성한 ChatModel 빈 검색
        discoverSpringAiModels();

        // 2. 커스텀 ModelProvider 빈 검색
        discoverAndRegisterProviders();

        // 3. 설정 파일의 모델 로드
        loadModelsFromConfiguration();

        // 4. Tier 매핑 빌드
        buildTierMapping();

        // 5. 헬스 체크
        performHealthCheck();

        log.info("DynamicModelRegistry initialized. Providers: {}, Models: {}",
                providers.size(), modelDescriptors.size());
    }

    /**
     * Spring AI가 자동 생성한 ChatModel 빈을 검색하여 등록합니다.
     * Gemini, Mistral 등 Spring AI가 지원하는 모든 ChatModel을 자동 발견합니다.
     */
    private void discoverSpringAiModels() {
        Map<String, ChatModel> chatModels = applicationContext.getBeansOfType(ChatModel.class);

        for (Map.Entry<String, ChatModel> entry : chatModels.entrySet()) {

            ChatModel model = entry.getValue();
            String provider = inferProviderFromModel(model);

            // 이미 등록된 프로바이더는 건너뜀
            if (!providers.containsKey(provider)) {
                // 자동 래퍼 프로바이더 생성
                AutoDiscoveredModelProvider autoProvider = new AutoDiscoveredModelProvider(provider, model);
                providers.put(provider, autoProvider);

                // 모델 디스크립터도 등록
                ModelDescriptor descriptor = autoProvider.getAvailableModels().stream()
                        .findFirst()
                        .orElse(null);
                if (descriptor != null) {
                    registerModel(descriptor);
                    modelInstances.put(descriptor.getModelId(), model);
                }

            }
        }
    }

    /**
     * ChatModel 클래스명에서 프로바이더를 추론합니다.
     */
    private String inferProviderFromModel(ChatModel model) {
        String className = model.getClass().getSimpleName().toLowerCase();

        if (className.contains("ollama"))
            return "ollama";
        if (className.contains("anthropic"))
            return "anthropic";
        if (className.contains("openai"))
            return "openai";
        if (className.contains("gemini") || className.contains("vertex"))
            return "gemini";
        if (className.contains("mistral"))
            return "mistral";
        if (className.contains("azure"))
            return "azure";
        if (className.contains("bedrock"))
            return "bedrock";
        if (className.contains("huggingface") || className.contains("hf"))
            return "huggingface";

        // Unknown provider
        log.warn("Unknown ChatModel type: {}. Registering as 'unknown' provider.", className);
        return "unknown-" + className;
    }

    private void discoverAndRegisterProviders() {

        Map<String, ModelProvider> providerBeans = applicationContext.getBeansOfType(ModelProvider.class);

        for (Map.Entry<String, ModelProvider> entry : providerBeans.entrySet()) {
            ModelProvider provider = entry.getValue();
            String providerName = provider.getProviderName();

            providers.put(providerName, provider);

            try {
                provider.initialize(Collections.emptyMap());

                List<ModelDescriptor> models = provider.getAvailableModels();
                for (ModelDescriptor model : models) {
                    registerModel(model);
                }
            } catch (Exception e) {
                log.error("ModelProvider initialization failed: {}", providerName, e);
            }
        }

    }

    private void loadModelsFromConfiguration() {

        registerModelFromConfig(1, tieredLLMProperties.getLayer1().getModel());
        if (tieredLLMProperties.getLayer1().hasBackupModel()) {
            registerModelFromConfig(1, tieredLLMProperties.getLayer1().getBackup().getModel());
        }

        registerModelFromConfig(2, tieredLLMProperties.getLayer2().getModel());
        if (tieredLLMProperties.getLayer2().hasBackupModel()) {
            registerModelFromConfig(2, tieredLLMProperties.getLayer2().getBackup().getModel());
        }

    }

    private void registerModelFromConfig(int tier, String modelName) {
        if (modelName == null || modelName.trim().isEmpty()) {
            return;
        }

        if (modelDescriptors.containsKey(modelName)) {
            ModelDescriptor existing = modelDescriptors.get(modelName);
            if (existing.getTier() == null) {
                existing.setTier(tier);
            }
            return;
        }

        ModelDescriptor descriptor = createDescriptorFromConfig(modelName, tier);
        registerModel(descriptor);
    }

    private ModelDescriptor createDescriptorFromConfig(String modelName, int tier) {
        String provider = modelProviderProperties.getProviderForModel(modelName);
        ModelProviderProperties.ModelSpec spec = modelProviderProperties.getModelSpec(provider, modelName);

        if (spec != null) {
            return createDescriptorFromSpec(modelName, spec, provider);
        }

        // ModelSpec이 없는 경우 TierDefaults 사용
        ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults = modelProviderProperties
                .getTierDefaults(tier);

        // TierDefaults도 없으면 최소 필수 정보만으로 ModelDescriptor 생성
        // 상세 정보(capabilities, performance, cost, options)는 알 수 없으므로 설정하지 않음
        if (tierDefaults == null) {
            return ModelDescriptor.builder()
                    .modelId(modelName)
                    .displayName(modelName)
                    .provider(provider)
                    .tier(tier)
                    .status(ModelDescriptor.ModelStatus.AVAILABLE)
                    .build();
        }

        return ModelDescriptor.builder()
                .modelId(modelName)
                .displayName(modelName)
                .provider(provider)
                .tier(tier)
                .capabilities(buildCapabilitiesFromDefaults(tierDefaults))
                .performance(buildPerformanceFromDefaults(tierDefaults))
                .options(ModelDescriptor.ModelOptions.builder()
                        .temperature(tierDefaults.getTemperature())
                        .build())
                .status(ModelDescriptor.ModelStatus.AVAILABLE)
                .build();
    }

    private ModelDescriptor createDescriptorFromSpec(String modelName, ModelProviderProperties.ModelSpec spec,
            String provider) {
        ModelDescriptor.ThroughputLevel throughput = ModelDescriptor.ThroughputLevel.valueOf(
                spec.getPerformance().getThroughputLevel());

        return ModelDescriptor.builder()
                .modelId(modelName)
                .displayName(spec.getDisplayName())
                .provider(provider)
                .version(spec.getVersion())
                .modelSize(spec.getModelSize())
                .tier(spec.getTier())
                .capabilities(ModelDescriptor.ModelCapabilities.builder()
                        .streaming(spec.getCapabilities().getStreaming())
                        .toolCalling(spec.getCapabilities().getToolCalling())
                        .functionCalling(spec.getCapabilities().getFunctionCalling())
                        .vision(spec.getCapabilities().getVision())
                        .multiModal(spec.getCapabilities().getMultiModal())
                        .maxTokens(spec.getCapabilities().getMaxTokens())
                        .contextWindow(spec.getCapabilities().getContextWindow())
                        .supportsSystemMessage(spec.getCapabilities().getSupportsSystemMessage())
                        .maxOutputTokens(spec.getCapabilities().getMaxOutputTokens())
                        .build())
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
                .metadata(spec.getMetadata())
                .build();
    }

    private ModelDescriptor.ModelCapabilities buildCapabilitiesFromDefaults(
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults) {
        // 알 수 없는 기능은 false로 설정 (임의 threshold 사용하지 않음)
        return ModelDescriptor.ModelCapabilities.builder()
                .streaming(true)
                .toolCalling(false)
                .functionCalling(false)
                .vision(false)
                .multiModal(false)
                .maxTokens(tierDefaults.getMaxTokens())
                .contextWindow(tierDefaults.getContextWindow())
                .supportsSystemMessage(true)
                .build();
    }

    private ModelDescriptor.PerformanceProfile buildPerformanceFromDefaults(
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults) {
        int tier = inferTierFromDefaults(tierDefaults);

        return ModelDescriptor.PerformanceProfile.builder()
                .latency(tierDefaults.getLatencyMs())
                .throughput(tier == 1 ? ModelDescriptor.ThroughputLevel.HIGH
                        : tier == 2 ? ModelDescriptor.ThroughputLevel.MEDIUM : ModelDescriptor.ThroughputLevel.LOW)
                .concurrency(tierDefaults.getConcurrency())
                .recommendedTimeout(tierDefaults.getTimeoutMs())
                .performanceScore(tierDefaults.getPerformanceScore())
                .build();
    }

    private int inferTierFromDefaults(ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults) {

        if (tierDefaults.getPerformanceScore() >= 90.0 && tierDefaults.getLatencyMs() <= 100) {
            return 1;
        } else {
            return 2;
        }
    }

    private void buildTierMapping() {
        tierModels.clear();

        for (ModelDescriptor descriptor : modelDescriptors.values()) {
            if (descriptor.getTier() != null) {
                tierModels.computeIfAbsent(descriptor.getTier(), k -> new ArrayList<>())
                        .add(descriptor.getModelId());
            }
        }

    }

    private void performHealthCheck() {

        for (Map.Entry<String, ModelProvider> entry : providers.entrySet()) {
            String providerName = entry.getKey();
            ModelProvider provider = entry.getValue();

            if (!provider.isReady()) {
                log.warn("ModelProvider {} is not ready", providerName);
                continue;
            }

            for (ModelDescriptor model : provider.getAvailableModels()) {
                try {
                    ModelProvider.HealthStatus health = provider.checkHealth(model.getModelId());
                    if (!health.isHealthy()) {
                        log.warn("Model {} unhealthy: {}", model.getModelId(), health.getMessage());
                        model.setStatus(ModelDescriptor.ModelStatus.UNAVAILABLE);
                    }
                } catch (Exception e) {
                    log.error("Model {} health check failed", model.getModelId(), e);
                }
            }
        }
    }

    public void registerModel(ModelDescriptor descriptor) {
        if (descriptor == null || descriptor.getModelId() == null) {
            return;
        }

        modelDescriptors.put(descriptor.getModelId(), descriptor);
    }

    public ChatModel getModel(String modelId) {
        if (modelId == null) {
            throw new ModelSelectionException("Model ID is null");
        }

        if (modelInstances.containsKey(modelId)) {
            return modelInstances.get(modelId);
        }

        ModelDescriptor descriptor = modelDescriptors.get(modelId);
        if (descriptor == null) {
            throw new ModelSelectionException("Model not found: " + modelId, modelId);
        }

        ModelProvider provider = providers.get(descriptor.getProvider());
        if (provider == null) {
            throw new ModelSelectionException(
                    "Model provider not found: " + descriptor.getProvider(), modelId);
        }

        try {
            ChatModel model = provider.createModel(descriptor);
            modelInstances.put(modelId, model);
            return model;
        } catch (Exception e) {
            throw new ModelSelectionException(
                    "Model creation failed: " + modelId + " - " + e.getMessage(), modelId, e);
        }
    }

    public List<ModelDescriptor> getModelsByTier(int tier) {
        List<String> modelIds = tierModels.get(tier);
        if (modelIds == null || modelIds.isEmpty()) {
            return Collections.emptyList();
        }

        return modelIds.stream()
                .map(modelDescriptors::get)
                .filter(Objects::nonNull)
                .filter(d -> d.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .collect(Collectors.toList());
    }

    public Collection<ModelDescriptor> getAllModels() {
        return new ArrayList<>(modelDescriptors.values());
    }

    /**
     * 특정 프로바이더의 사용 가능한 모델 목록을 반환합니다.
     * Priority 기반 모델 선택에 사용됩니다.
     *
     * @param provider 프로바이더 이름 (ollama, anthropic, openai, gemini 등)
     * @return 해당 프로바이더의 사용 가능한 모델 목록
     */
    public List<ModelDescriptor> getModelsByProvider(String provider) {
        if (provider == null || provider.trim().isEmpty()) {
            return Collections.emptyList();
        }

        String normalizedProvider = provider.trim().toLowerCase();
        return modelDescriptors.values().stream()
                .filter(d -> normalizedProvider.equalsIgnoreCase(d.getProvider()))
                .filter(d -> d.getStatus() == ModelDescriptor.ModelStatus.AVAILABLE)
                .toList();
    }

    public void updateModelStatus(String modelId, ModelDescriptor.ModelStatus status) {
        ModelDescriptor descriptor = modelDescriptors.get(modelId);
        if (descriptor != null) {
            descriptor.setStatus(status);
        }
    }

    public void refreshModels() {

        for (ModelProvider provider : providers.values()) {
            try {
                provider.refreshModels();

                for (ModelDescriptor model : provider.getAvailableModels()) {
                    if (!modelDescriptors.containsKey(model.getModelId())) {
                        registerModel(model);
                    }
                }
            } catch (Exception e) {
                log.error("Model refresh failed: {}", provider.getProviderName(), e);
            }
        }

        buildTierMapping();

    }

    @PreDestroy
    public void shutdown() {

        for (ModelProvider provider : providers.values()) {
            try {
                provider.shutdown();
            } catch (Exception e) {
                log.error("ModelProvider shutdown failed: {}", provider.getProviderName(), e);
            }
        }

        modelInstances.clear();
        modelDescriptors.clear();
        providers.clear();
    }
}