package io.contexa.contexacore.std.llm.model;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring AI가 자동 생성한 ChatModel을 래핑하는 프로바이더입니다.
 * Gemini, Mistral 등 새로운 프로바이더가 Spring AI에 의해 자동 구성되면
 * 이 클래스가 해당 ChatModel을 래핑하여 DynamicModelRegistry에 등록합니다.
 */
@Slf4j
public class AutoDiscoveredModelProvider implements ModelProvider {

    private final String providerName;
    private final ChatModel chatModel;
    private final ModelDescriptor modelDescriptor;
    private boolean ready = false;

    public AutoDiscoveredModelProvider(String providerName, ChatModel chatModel) {
        this.providerName = providerName;
        this.chatModel = chatModel;
        this.modelDescriptor = createModelDescriptor();
        this.ready = chatModel != null;

        log.info("AutoDiscoveredModelProvider 생성: provider={}, model={}",
            providerName, chatModel != null ? chatModel.getClass().getSimpleName() : "null");
    }

    private ModelDescriptor createModelDescriptor() {
        String modelId = providerName + "-default";
        String displayName = providerName.substring(0, 1).toUpperCase() +
            providerName.substring(1) + " (Auto-discovered)";

        return ModelDescriptor.builder()
            .modelId(modelId)
            .displayName(displayName)
            .provider(providerName)
            .status(chatModel != null ?
                ModelDescriptor.ModelStatus.AVAILABLE :
                ModelDescriptor.ModelStatus.UNAVAILABLE)
            .capabilities(ModelDescriptor.ModelCapabilities.builder()
                .streaming(true)
                .toolCalling(true)
                .functionCalling(true)
                .supportsSystemMessage(true)
                .build())
            .performance(ModelDescriptor.PerformanceProfile.builder()
                .latency(500)
                .throughput(ModelDescriptor.ThroughputLevel.MEDIUM)
                .concurrency(10)
                .recommendedTimeout(30000)
                .performanceScore(70.0)
                .build())
            .cost(ModelDescriptor.CostProfile.builder()
                .costPerInputToken(0.0)
                .costPerOutputToken(0.0)
                .costEfficiency(100.0)
                .build())
            .options(ModelDescriptor.ModelOptions.builder()
                .temperature(0.7)
                .topP(0.9)
                .build())
            .build();
    }

    @Override
    public String getProviderName() {
        return providerName;
    }

    @Override
    public String getDescription() {
        return "Auto-discovered " + providerName + " provider via Spring AI";
    }

    @Override
    public List<ModelDescriptor> getAvailableModels() {
        if (modelDescriptor == null) {
            return Collections.emptyList();
        }
        return List.of(modelDescriptor);
    }

    @Override
    public ModelDescriptor getModelDescriptor(String modelId) {
        if (modelDescriptor != null && modelDescriptor.getModelId().equals(modelId)) {
            return modelDescriptor;
        }
        return null;
    }

    @Override
    public ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config) {
        // 자동 발견된 ChatModel은 이미 생성되어 있으므로 그대로 반환
        return chatModel;
    }

    @Override
    public boolean supportsModelType(String modelType) {
        return ModelType.CHAT.equals(modelType);
    }

    @Override
    public boolean supportsModel(String modelId) {
        return modelDescriptor != null && modelDescriptor.getModelId().equals(modelId);
    }

    @Override
    public HealthStatus checkHealth(String modelId) {
        if (chatModel == null) {
            return HealthStatus.unhealthy("ChatModel is null");
        }
        return HealthStatus.healthy();
    }

    @Override
    public void initialize(Map<String, Object> config) {
        // 자동 발견된 ChatModel은 Spring에 의해 이미 초기화되어 있음
        ready = chatModel != null;
        log.debug("AutoDiscoveredModelProvider 초기화: provider={}, ready={}",
            providerName, ready);
    }

    @Override
    public void shutdown() {
        // 자동 발견된 ChatModel의 생명주기는 Spring이 관리
        ready = false;
        log.debug("AutoDiscoveredModelProvider 종료: provider={}", providerName);
    }

    @Override
    public boolean isReady() {
        return ready && chatModel != null;
    }

    @Override
    public void refreshModels() {
        // 자동 발견된 모델은 새로고침 불필요
        log.debug("AutoDiscoveredModelProvider 새로고침 (no-op): provider={}", providerName);
    }

    @Override
    public int getPriority() {
        // 자동 발견된 프로바이더는 낮은 우선순위 (명시적 구성 우선)
        return 50;
    }

    @Override
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("provider", providerName);
        metrics.put("ready", ready);
        metrics.put("autoDiscovered", true);
        metrics.put("modelClass", chatModel != null ? chatModel.getClass().getName() : "null");
        return metrics;
    }
}
