package io.contexa.contexacore.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Data
@ConfigurationProperties(prefix = "spring.ai.providers")
public class ModelProviderProperties {

    /**
     * Provider 설정의 공통 인터페이스
     */
    public interface BaseProviderConfig {
        boolean isEnabled();
        String getBaseUrl();
        Map<String, ModelSpec> getModels();
    }

    @NestedConfigurationProperty
    private OllamaConfig ollama = new OllamaConfig();

    @NestedConfigurationProperty
    private AnthropicConfig anthropic = new AnthropicConfig();

    @NestedConfigurationProperty
    private OpenAIConfig openai = new OpenAIConfig();

    @NestedConfigurationProperty
    private VLLMConfig vllm = new VLLMConfig();

    @NestedConfigurationProperty
    private Map<String, String> providerMapping = new HashMap<>();

    @NestedConfigurationProperty
    private DefaultSpecs defaults = new DefaultSpecs();

    @Data
    public static class OllamaConfig implements BaseProviderConfig {
        private String baseUrl = "http://127.0.0.1:11434";
        private boolean enabled = true;
        private ApiEndpoints api = new ApiEndpoints();
        private Map<String, ModelSpec> models = new HashMap<>();
        private PerformanceDefaults performance = new PerformanceDefaults();

        @Data
        public static class ApiEndpoints {
            private String tags = "/api/tags";
            private String generate = "/api/generate";
            private String chat = "/api/chat";
            private String embeddings = "/api/embeddings";
            private String show = "/api/show";
        }

        @Data
        public static class PerformanceDefaults {
            private Integer latencyMs = 100;
            private Integer timeoutMs = 5000;
            private Double performanceScore = 85.0;
            private Integer concurrency = 100;
        }
    }

    @Data
    public static class AnthropicConfig implements BaseProviderConfig {
        private String baseUrl = "https://api.anthropic.com";
        private boolean enabled = true;
        private Map<String, ModelSpec> models = new HashMap<>();
    }

    @Data
    public static class OpenAIConfig implements BaseProviderConfig {
        private String baseUrl = "https://api.openai.com";
        private boolean enabled = true;
        private Map<String, ModelSpec> models = new HashMap<>();
    }

    @Data
    public static class VLLMConfig implements BaseProviderConfig {
        private String baseUrl = "http://localhost:8000";
        private boolean enabled = false;
        private Map<String, ModelSpec> models = new HashMap<>();
        private PerformanceDefaults performance = new PerformanceDefaults();

        @Data
        public static class PerformanceDefaults {
            private Integer latencyMs = 50;  
            private Integer timeoutMs = 5000;
            private Double performanceScore = 95.0;  
            private Integer concurrency = 200;  
            private Integer throughputMultiplier = 10;  
        }
    }

    @Data
    public static class ModelSpec {
        private String displayName;
        private String version;
        private String modelSize;
        private Integer tier;

        private ModelCapabilities capabilities = new ModelCapabilities();

        private PerformanceSpec performance = new PerformanceSpec();

        private CostSpec cost = new CostSpec();

        private ModelOptions options = new ModelOptions();

        private Map<String, Object> metadata = new HashMap<>();

        @Data
        public static class ModelCapabilities {
            private Boolean streaming = true;
            private Boolean toolCalling = false;
            private Boolean functionCalling = false;
            private Boolean vision = false;
            private Boolean multiModal = false;
            private Integer maxTokens = 4096;
            private Integer contextWindow = 4096;
            private Boolean supportsSystemMessage = true;
            private Integer maxOutputTokens = 4096;
        }

        @Data
        public static class PerformanceSpec {
            private Integer latencyMs = 1000;
            private String throughputLevel = "MEDIUM"; 
            private Integer concurrency = 50;
            private Integer recommendedTimeoutMs = 5000;
            private Double performanceScore = 75.0;
        }

        @Data
        public static class CostSpec {
            private Double costPerInputToken = 0.0;
            private Double costPerOutputToken = 0.0;
            private Double costEfficiency = 100.0;
            private String billingModel = "per-token"; 
        }

        @Data
        public static class ModelOptions {
            private Double temperature = 0.5;
            private Double topP = 0.9;
            private Integer topK = 40;
            private Double repetitionPenalty = 1.0;
            private Double frequencyPenalty = 0.0;
            private Double presencePenalty = 0.0;
        }
    }

    @Data
    public static class DefaultSpecs {
        private Map<Integer, TierDefaults> tierDefaults = new HashMap<>();

        @Data
        public static class TierDefaults {
            private Integer timeoutMs = 5000;
            private Double temperature = 0.5;
            private Integer maxTokens = 4096;
            private Integer contextWindow = 4096;
            private Double performanceScore = 75.0;
            private Integer latencyMs = 1000;
            private Integer concurrency = 50;
        }
    }

    public String getProviderForModel(String modelName) {
        if (modelName == null || modelName.isEmpty()) {
            return "unknown";
        }

        for (Map.Entry<String, String> entry : providerMapping.entrySet()) {
            String pattern = entry.getKey();
            if (modelName.matches(pattern) || modelName.startsWith(pattern)) {
                return entry.getValue();
            }
        }

        if (ollama.getModels().containsKey(modelName)) {
            return "ollama";
        }

        if (anthropic.getModels().containsKey(modelName)) {
            return "anthropic";
        }

        if (openai.getModels().containsKey(modelName)) {
            return "openai";
        }

        if (vllm.getModels().containsKey(modelName)) {
            return "vllm";
        }

                return "unknown";
    }

    public ModelSpec getModelSpec(String provider, String modelName) {
        switch (provider.toLowerCase()) {
            case "ollama":
                return ollama.getModels().get(modelName);
            case "anthropic":
                return anthropic.getModels().get(modelName);
            case "openai":
                return openai.getModels().get(modelName);
            case "vllm":
                return vllm.getModels().get(modelName);
            default:
                return null;
        }
    }

    public DefaultSpecs.TierDefaults getTierDefaults(int tier) {
        return defaults.getTierDefaults().get(tier);
    }

    @PostConstruct
    public void validateConfiguration() {

        if (ollama.isEnabled()) {
                        for (String modelId : ollama.getModels().keySet()) {
                            }
        }

        if (anthropic.isEnabled()) {
                        for (String modelId : anthropic.getModels().keySet()) {
                            }
        }

        if (openai.isEnabled()) {
                        for (String modelId : openai.getModels().keySet()) {
                            }
        }

        if (vllm.isEnabled()) {
                        for (String modelId : vllm.getModels().keySet()) {
                            }
        }

                for (Map.Entry<String, String> entry : providerMapping.entrySet()) {
                    }

                for (Map.Entry<Integer, DefaultSpecs.TierDefaults> entry : defaults.getTierDefaults().entrySet()) {
            DefaultSpecs.TierDefaults td = entry.getValue();
                    }

            }
}