package io.contexa.contexacore.std.llm.model;

import org.springframework.ai.chat.model.ChatModel;

import java.util.List;
import java.util.Map;


public interface ModelProvider {

    
    String getProviderName();

    
    String getDescription();

    
    List<ModelDescriptor> getAvailableModels();

    
    ModelDescriptor getModelDescriptor(String modelId);

    
    ChatModel createModel(ModelDescriptor descriptor, Map<String, Object> config);

    
    default ChatModel createModel(ModelDescriptor descriptor) {
        return createModel(descriptor, null);
    }

    
    default ChatModel createModelById(String modelId, Map<String, Object> config) {
        ModelDescriptor descriptor = getModelDescriptor(modelId);
        if (descriptor == null) {
            throw new IllegalArgumentException("Model not found: " + modelId);
        }
        return createModel(descriptor, config);
    }

    
    boolean supportsModelType(String modelType);

    
    boolean supportsModel(String modelId);

    
    HealthStatus checkHealth(String modelId);

    
    void initialize(Map<String, Object> config);

    
    void shutdown();

    
    boolean isReady();

    
    void refreshModels();

    
    default int getPriority() {
        return 100;
    }

    
    Map<String, Object> getMetrics();

    
    class HealthStatus {
        private final boolean healthy;
        private final String message;
        private final long responseTimeMs;
        private final Map<String, Object> details;

        public HealthStatus(boolean healthy, String message, long responseTimeMs, Map<String, Object> details) {
            this.healthy = healthy;
            this.message = message;
            this.responseTimeMs = responseTimeMs;
            this.details = details;
        }

        public static HealthStatus healthy() {
            return new HealthStatus(true, "Healthy", 0, null);
        }

        public static HealthStatus unhealthy(String message) {
            return new HealthStatus(false, message, -1, null);
        }

        public boolean isHealthy() {
            return healthy;
        }

        public String getMessage() {
            return message;
        }

        public long getResponseTimeMs() {
            return responseTimeMs;
        }

        public Map<String, Object> getDetails() {
            return details;
        }
    }

    
    interface ModelType {
        String CHAT = "chat";
        String EMBEDDING = "embedding";
        String COMPLETION = "completion";
        String IMAGE = "image";
        String AUDIO = "audio";
    }
}