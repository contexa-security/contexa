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

        discoverAndRegisterProviders();

        loadModelsFromConfiguration();

        buildTierMapping();

        performHealthCheck();

            }

    private void discoverAndRegisterProviders() {
        
        Map<String, ModelProvider> providerBeans =
            applicationContext.getBeansOfType(ModelProvider.class);

        for (Map.Entry<String, ModelProvider> entry : providerBeans.entrySet()) {
            ModelProvider provider = entry.getValue();
            String providerName = provider.getProviderName();

            providers.put(providerName, provider);

            try {
                provider.initialize(getProviderConfig(providerName));

                List<ModelDescriptor> models = provider.getAvailableModels();
                for (ModelDescriptor model : models) {
                    registerModel(model);
                }
            } catch (Exception e) {
                log.error("ModelProvider 초기화 실패: {}", providerName, e);
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
        } else {
            
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
                modelProviderProperties.getTierDefaults(tier);

            if (tierDefaults == null) {
                tierDefaults = new ModelProviderProperties.DefaultSpecs.TierDefaults();
                tierDefaults.setTimeoutMs(tier == 1 ? 3000 : tier == 2 ? 10000 : 30000);
                tierDefaults.setTemperature(0.3);
                tierDefaults.setMaxTokens(tier == 1 ? 100 : tier == 2 ? 500 : 2000);
                tierDefaults.setContextWindow(tier == 1 ? 4096 : tier == 2 ? 8192 : 32768);
                tierDefaults.setLatencyMs(tier == 1 ? 50 : tier == 2 ? 500 : 2000);
                tierDefaults.setConcurrency(tier == 1 ? 100 : tier == 2 ? 50 : 10);
                tierDefaults.setPerformanceScore(tier == 1 ? 95.0 : tier == 2 ? 80.0 : 60.0);
            }

            return ModelDescriptor.builder()
                .modelId(modelName)
                .displayName(modelName)
                .provider(provider)
                .tier(tier)
                .capabilities(buildCapabilitiesFromDefaults(tierDefaults))
                .performance(buildPerformanceFromDefaults(tierDefaults))
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
                .build();
        }
    }

    private ModelDescriptor createDescriptorFromSpec(String modelName, ModelProviderProperties.ModelSpec spec, String provider) {
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

    private ModelDescriptor.ModelCapabilities buildCapabilitiesFromDefaults(ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults) {
        return ModelDescriptor.ModelCapabilities.builder()
            .streaming(true)
            .toolCalling(tierDefaults.getMaxTokens() > 100000)
            .functionCalling(tierDefaults.getMaxTokens() > 100000)
            .vision(false)
            .multiModal(false)
            .maxTokens(tierDefaults.getMaxTokens())
            .contextWindow(tierDefaults.getContextWindow())
            .supportsSystemMessage(true)
            .build();
    }

    private ModelDescriptor.PerformanceProfile buildPerformanceFromDefaults(ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults) {
        int tier = inferTierFromDefaults(tierDefaults);

        return ModelDescriptor.PerformanceProfile.builder()
            .latency(tierDefaults.getLatencyMs())
            .throughput(tier == 1 ?
                ModelDescriptor.ThroughputLevel.HIGH :
                tier == 2 ?
                ModelDescriptor.ThroughputLevel.MEDIUM :
                ModelDescriptor.ThroughputLevel.LOW)
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
                log.warn("ModelProvider {} 가 준비되지 않았습니다", providerName);
                continue;
            }

            for (ModelDescriptor model : provider.getAvailableModels()) {
                try {
                    ModelProvider.HealthStatus health = provider.checkHealth(model.getModelId());
                    if (!health.isHealthy()) {
                        log.warn("모델 {} 상태 불량: {}", model.getModelId(), health.getMessage());
                        model.setStatus(ModelDescriptor.ModelStatus.UNAVAILABLE);
                    }
                } catch (Exception e) {
                    log.error("모델 {} 헬스 체크 실패", model.getModelId(), e);
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
            throw new ModelSelectionException("모델 ID가 null입니다");
        }

        if (modelInstances.containsKey(modelId)) {
            return modelInstances.get(modelId);
        }

        ModelDescriptor descriptor = modelDescriptors.get(modelId);
        if (descriptor == null) {
            throw new ModelSelectionException("모델을 찾을 수 없습니다: " + modelId, modelId);
        }

        ModelProvider provider = providers.get(descriptor.getProvider());
        if (provider == null) {
            throw new ModelSelectionException(
                "모델 제공자를 찾을 수 없습니다: " + descriptor.getProvider(), modelId);
        }

        try {
            ChatModel model = provider.createModel(descriptor);
            modelInstances.put(modelId, model);
            return model;
        } catch (Exception e) {
            throw new ModelSelectionException(
                "모델 생성 실패: " + modelId + " - " + e.getMessage(), modelId, e);
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
                log.error("모델 새로고침 실패: {}", provider.getProviderName(), e);
            }
        }

        buildTierMapping();

            }

    private Map<String, Object> getProviderConfig(String providerName) {
        Map<String, Object> config = new HashMap<>();

        return config;
    }

    @PreDestroy
    public void shutdown() {

        for (ModelProvider provider : providers.values()) {
            try {
                provider.shutdown();
            } catch (Exception e) {
                log.error("ModelProvider 종료 실패: {}", provider.getProviderName(), e);
            }
        }

        modelInstances.clear();
        modelDescriptors.clear();
        providers.clear();
    }
}