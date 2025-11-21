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

/**
 * 동적 모델 레지스트리
 *
 * 모든 사용 가능한 모델을 중앙에서 관리하고,
 * 런타임에 동적으로 모델을 발견, 등록, 생성합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class DynamicModelRegistry {

    private final ApplicationContext applicationContext;
    private final TieredLLMProperties tieredLLMProperties;
    private final ModelProviderProperties modelProviderProperties;

    /**
     * 모델 제공자 맵 (provider name -> provider instance)
     */
    private final Map<String, ModelProvider> providers = new ConcurrentHashMap<>();

    /**
     * 모델 디스크립터 맵 (model id -> descriptor)
     */
    private final Map<String, ModelDescriptor> modelDescriptors = new ConcurrentHashMap<>();

    /**
     * 모델 인스턴스 캐시 (model id -> model instance)
     */
    private final Map<String, ChatModel> modelInstances = new ConcurrentHashMap<>();

    /**
     * Tier별 모델 맵핑 (tier -> list of model ids)
     */
    private final Map<Integer, List<String>> tierModels = new ConcurrentHashMap<>();

    /**
     * 초기화
     */
    @PostConstruct
    public void initialize() {
        log.info("DynamicModelRegistry 초기화 시작");

        // 1. 모든 ModelProvider 구현체 자동 발견 및 등록
        discoverAndRegisterProviders();

        // 2. 설정 파일에서 모델 정의 로드
        loadModelsFromConfiguration();

        // 3. Tier별 모델 매핑 구성
        buildTierMapping();

        // 4. 초기 헬스 체크
        performHealthCheck();

        log.info("DynamicModelRegistry 초기화 완료 - 등록된 모델: {}", modelDescriptors.size());
    }

    /**
     * ModelProvider 구현체 자동 발견 및 등록
     */
    private void discoverAndRegisterProviders() {
        log.info("ModelProvider 구현체 자동 발견 시작");

        Map<String, ModelProvider> providerBeans =
            applicationContext.getBeansOfType(ModelProvider.class);

        for (Map.Entry<String, ModelProvider> entry : providerBeans.entrySet()) {
            ModelProvider provider = entry.getValue();
            String providerName = provider.getProviderName();

            providers.put(providerName, provider);
            log.info("ModelProvider 등록: {} ({})", providerName, provider.getClass().getSimpleName());

            // 제공자 초기화
            try {
                provider.initialize(getProviderConfig(providerName));

                // 제공자가 제공하는 모델들 등록
                List<ModelDescriptor> models = provider.getAvailableModels();
                for (ModelDescriptor model : models) {
                    registerModel(model);
                }
            } catch (Exception e) {
                log.error("ModelProvider 초기화 실패: {}", providerName, e);
            }
        }

        log.info("총 {} 개의 ModelProvider 등록됨", providers.size());
    }

    /**
     * 설정 파일에서 모델 정의 로드
     */
    private void loadModelsFromConfiguration() {
        log.info("설정 파일에서 모델 정의 로드");

        // Layer 1 모델
        registerModelFromConfig(1, tieredLLMProperties.getLayer1().getModel());
        if (tieredLLMProperties.getLayer1().hasBackupModel()) {
            registerModelFromConfig(1, tieredLLMProperties.getLayer1().getBackup().getModel());
        }

        // Layer 2 모델
        registerModelFromConfig(2, tieredLLMProperties.getLayer2().getModel());
        if (tieredLLMProperties.getLayer2().hasBackupModel()) {
            registerModelFromConfig(2, tieredLLMProperties.getLayer2().getBackup().getModel());
        }

        // Layer 3 모델
        registerModelFromConfig(3, tieredLLMProperties.getLayer3().getModel());
        if (tieredLLMProperties.getLayer3().hasBackupModel()) {
            registerModelFromConfig(3, tieredLLMProperties.getLayer3().getBackup().getModel());
        }
    }

    /**
     * 설정 파일의 모델 정보로 모델 등록
     */
    private void registerModelFromConfig(int tier, String modelName) {
        if (modelName == null || modelName.trim().isEmpty()) {
            return;
        }

        // 이미 등록된 모델이면 tier 정보만 업데이트
        if (modelDescriptors.containsKey(modelName)) {
            ModelDescriptor existing = modelDescriptors.get(modelName);
            if (existing.getTier() == null) {
                existing.setTier(tier);
            }
            return;
        }

        // 새로운 모델 디스크립터 생성
        ModelDescriptor descriptor = createDescriptorFromConfig(modelName, tier);
        registerModel(descriptor);
    }

    /**
     * 설정 기반 모델 디스크립터 생성
     */
    private ModelDescriptor createDescriptorFromConfig(String modelName, int tier) {
        String provider = modelProviderProperties.getProviderForModel(modelName);
        ModelProviderProperties.ModelSpec spec = modelProviderProperties.getModelSpec(provider, modelName);

        if (spec != null) {
            // 설정에서 스펙이 정의된 경우
            return createDescriptorFromSpec(modelName, spec, provider);
        } else {
            // 설정에 없는 경우 기본값 사용
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
                modelProviderProperties.getTierDefaults(tier);

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

    /**
     * 스펙으로부터 디스크립터 생성
     */
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


    /**
     * 기본값으로부터 기능 빌드
     */
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

    /**
     * 기본값으로부터 성능 프로파일 빌드
     */
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

    /**
     * 기본값으로부터 Tier 추론
     */
    private int inferTierFromDefaults(ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults) {
        // 성능 점수와 대기시간을 기준으로 Tier 추론
        if (tierDefaults.getPerformanceScore() >= 90.0 && tierDefaults.getLatencyMs() <= 100) {
            return 1;
        } else if (tierDefaults.getPerformanceScore() >= 70.0 && tierDefaults.getLatencyMs() <= 1000) {
            return 2;
        } else {
            return 3;
        }
    }



    /**
     * Tier별 모델 매핑 구성
     */
    private void buildTierMapping() {
        tierModels.clear();

        for (ModelDescriptor descriptor : modelDescriptors.values()) {
            if (descriptor.getTier() != null) {
                tierModels.computeIfAbsent(descriptor.getTier(), k -> new ArrayList<>())
                    .add(descriptor.getModelId());
            }
        }

        log.info("Tier별 모델 매핑 완료: {}", tierModels);
    }

    /**
     * 초기 헬스 체크
     */
    private void performHealthCheck() {
        log.info("모델 헬스 체크 시작");

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

    /**
     * 모델 등록
     */
    public void registerModel(ModelDescriptor descriptor) {
        if (descriptor == null || descriptor.getModelId() == null) {
            return;
        }

        modelDescriptors.put(descriptor.getModelId(), descriptor);
        log.debug("모델 등록: {} (Tier: {}, Provider: {})",
            descriptor.getModelId(), descriptor.getTier(), descriptor.getProvider());
    }

    /**
     * 모델 ID로 모델 인스턴스 반환
     */
    public ChatModel getModel(String modelId) {
        if (modelId == null) {
            throw new ModelSelectionException("모델 ID가 null입니다");
        }

        // 캐시 확인
        if (modelInstances.containsKey(modelId)) {
            return modelInstances.get(modelId);
        }

        // 모델 디스크립터 확인
        ModelDescriptor descriptor = modelDescriptors.get(modelId);
        if (descriptor == null) {
            throw new ModelSelectionException("모델을 찾을 수 없습니다: " + modelId, modelId);
        }

        // 제공자 확인
        ModelProvider provider = providers.get(descriptor.getProvider());
        if (provider == null) {
            throw new ModelSelectionException(
                "모델 제공자를 찾을 수 없습니다: " + descriptor.getProvider(), modelId);
        }

        // 모델 생성
        try {
            ChatModel model = provider.createModel(descriptor);
            modelInstances.put(modelId, model);
            return model;
        } catch (Exception e) {
            throw new ModelSelectionException(
                "모델 생성 실패: " + modelId + " - " + e.getMessage(), modelId, e);
        }
    }

    /**
     * Tier에 해당하는 모델 목록 반환
     */
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

    /**
     * 모든 모델 디스크립터 반환
     */
    public Collection<ModelDescriptor> getAllModels() {
        return new ArrayList<>(modelDescriptors.values());
    }

    /**
     * 모델 상태 업데이트
     */
    public void updateModelStatus(String modelId, ModelDescriptor.ModelStatus status) {
        ModelDescriptor descriptor = modelDescriptors.get(modelId);
        if (descriptor != null) {
            descriptor.setStatus(status);
            log.info("모델 {} 상태 변경: {}", modelId, status);
        }
    }

    /**
     * 모델 새로고침
     */
    public void refreshModels() {
        log.info("모델 목록 새로고침 시작");

        // 각 제공자별로 모델 새로고침
        for (ModelProvider provider : providers.values()) {
            try {
                provider.refreshModels();

                // 새로운 모델 등록
                for (ModelDescriptor model : provider.getAvailableModels()) {
                    if (!modelDescriptors.containsKey(model.getModelId())) {
                        registerModel(model);
                    }
                }
            } catch (Exception e) {
                log.error("모델 새로고침 실패: {}", provider.getProviderName(), e);
            }
        }

        // Tier 매핑 재구성
        buildTierMapping();

        log.info("모델 목록 새로고침 완료");
    }

    /**
     * 제공자별 설정 반환
     */
    private Map<String, Object> getProviderConfig(String providerName) {
        Map<String, Object> config = new HashMap<>();

        // 제공자별 설정을 application.yml에서 로드하는 로직
        // 예: spring.ai.providers.ollama.*

        return config;
    }

    /**
     * 종료 처리
     */
    @PreDestroy
    public void shutdown() {
        log.info("DynamicModelRegistry 종료");

        // 모든 제공자 종료
        for (ModelProvider provider : providers.values()) {
            try {
                provider.shutdown();
            } catch (Exception e) {
                log.error("ModelProvider 종료 실패: {}", provider.getProviderName(), e);
            }
        }

        // 캐시 정리
        modelInstances.clear();
        modelDescriptors.clear();
        providers.clear();
    }
}