package io.contexa.contexacore.std.llm.model;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Provider wrapping ChatModels auto-discovered by Spring AI.
 * When new providers are auto-configured by Spring AI (e.g., Gemini, Mistral),
 * this class wraps the corresponding ChatModel and registers it in
 * DynamicModelRegistry.
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

    }

    private ModelDescriptor createModelDescriptor() {
        String modelId = providerName + "-default";
        String displayName = providerName.substring(0, 1).toUpperCase() +
                providerName.substring(1) + " (Auto-discovered)";

        // 자동 발견된 모델의 경우 최소 필수 정보만 설정
        // 상세 정보(capabilities, performance, cost, options)는 알 수 없으므로 설정하지 않음
        return ModelDescriptor.builder()
                .modelId(modelId)
                .displayName(displayName)
                .provider(providerName)
                .status(chatModel != null ? ModelDescriptor.ModelStatus.AVAILABLE
                        : ModelDescriptor.ModelStatus.UNAVAILABLE)
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
        // Return pre-existing auto-discovered ChatModel
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
        // Auto-discovered ChatModel is already initialized by Spring
        ready = chatModel != null;
    }

    @Override
    public void shutdown() {
        // Lifecycle of auto-discovered ChatModel is managed by Spring
        ready = false;
    }

    @Override
    public boolean isReady() {
        return ready && chatModel != null;
    }

    @Override
    public void refreshModels() {
        // No refresh needed for auto-discovered models
    }

    @Override
    public int getPriority() {
        // Auto-discovered providers have lower priority (explicit configuration
        // preferred)
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
