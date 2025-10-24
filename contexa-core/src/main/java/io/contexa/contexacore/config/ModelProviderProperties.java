package io.contexa.contexacore.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

/**
 * 모델 제공자 통합 설정
 *
 * 모든 모델 제공자(Ollama, Anthropic, OpenAI 등)의 설정을 중앙에서 관리합니다.
 * 하드코딩 제거 및 동적 설정을 통해 코드 수정 없이 새 모델을 추가할 수 있습니다.
 */
@Slf4j
@Data
@Component
@ConfigurationProperties(prefix = "spring.ai.providers")
public class ModelProviderProperties {

    /**
     * Ollama 프로바이더 설정
     */
    @NestedConfigurationProperty
    private OllamaConfig ollama = new OllamaConfig();

    /**
     * Anthropic 프로바이더 설정
     */
    @NestedConfigurationProperty
    private AnthropicConfig anthropic = new AnthropicConfig();

    /**
     * OpenAI 프로바이더 설정
     */
    @NestedConfigurationProperty
    private OpenAIConfig openai = new OpenAIConfig();

    /**
     * 프로바이더 매핑 테이블
     * 모델명 패턴 -> 프로바이더 매핑
     */
    @NestedConfigurationProperty
    private Map<String, String> providerMapping = new HashMap<>();

    /**
     * 기본 모델 스펙 (프로바이더별 기본값)
     */
    @NestedConfigurationProperty
    private DefaultSpecs defaults = new DefaultSpecs();

    /**
     * Ollama 설정
     */
    @Data
    public static class OllamaConfig {
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

    /**
     * Anthropic 설정
     */
    @Data
    public static class AnthropicConfig {
        private String baseUrl = "https://api.anthropic.com";
        private boolean enabled = true;
        private Map<String, ModelSpec> models = new HashMap<>();
        private ApiConfig api = new ApiConfig();

        @Data
        public static class ApiConfig {
            private String messagesEndpoint = "/v1/messages";
            private String modelsEndpoint = "/v1/models";
            private Integer maxRetries = 3;
            private Integer retryDelayMs = 1000;
        }
    }

    /**
     * OpenAI 설정
     */
    @Data
    public static class OpenAIConfig {
        private String baseUrl = "https://api.openai.com";
        private boolean enabled = true;
        private Map<String, ModelSpec> models = new HashMap<>();
    }

    /**
     * 모델 상세 스펙
     */
    @Data
    public static class ModelSpec {
        private String displayName;
        private String version;
        private String modelSize;
        private Integer tier;

        // Capabilities
        private ModelCapabilities capabilities = new ModelCapabilities();

        // Performance
        private PerformanceSpec performance = new PerformanceSpec();

        // Cost
        private CostSpec cost = new CostSpec();

        // Options
        private ModelOptions options = new ModelOptions();

        // Metadata
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
            private String throughputLevel = "MEDIUM"; // HIGH, MEDIUM, LOW
            private Integer concurrency = 50;
            private Integer recommendedTimeoutMs = 5000;
            private Double performanceScore = 75.0;
        }

        @Data
        public static class CostSpec {
            private Double costPerInputToken = 0.0;
            private Double costPerOutputToken = 0.0;
            private Double costEfficiency = 100.0;
            private String billingModel = "per-token"; // per-token, per-request, subscription
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

    /**
     * 기본 스펙 설정
     */
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

    /**
     * 모델명으로 프로바이더 결정
     */
    public String getProviderForModel(String modelName) {
        if (modelName == null || modelName.isEmpty()) {
            return "unknown";
        }

        // 매핑 테이블에서 먼저 확인
        for (Map.Entry<String, String> entry : providerMapping.entrySet()) {
            String pattern = entry.getKey();
            if (modelName.matches(pattern) || modelName.startsWith(pattern)) {
                return entry.getValue();
            }
        }

        // Ollama 모델 확인
        if (ollama.getModels().containsKey(modelName)) {
            return "ollama";
        }

        // Anthropic 모델 확인
        if (anthropic.getModels().containsKey(modelName)) {
            return "anthropic";
        }

        // OpenAI 모델 확인
        if (openai.getModels().containsKey(modelName)) {
            return "openai";
        }

        log.debug("프로바이더를 찾을 수 없음: {}", modelName);
        return "unknown";
    }

    /**
     * 모델 스펙 조회
     */
    public ModelSpec getModelSpec(String provider, String modelName) {
        switch (provider.toLowerCase()) {
            case "ollama":
                return ollama.getModels().get(modelName);
            case "anthropic":
                return anthropic.getModels().get(modelName);
            case "openai":
                return openai.getModels().get(modelName);
            default:
                return null;
        }
    }

    /**
     * Tier별 기본값 조회
     */
    public DefaultSpecs.TierDefaults getTierDefaults(int tier) {
        return defaults.getTierDefaults().get(tier);
    }

    /**
     * 설정 초기화 후 검증
     */
    @PostConstruct
    public void validateConfiguration() {
        log.info("모델 제공자 설정 검증 시작");

        // Ollama 설정 검증
        if (ollama.isEnabled()) {
            log.info("Ollama 설정: baseUrl={}, 모델 수={}",
                    ollama.getBaseUrl(), ollama.getModels().size());
            for (String modelId : ollama.getModels().keySet()) {
                log.debug("  - Ollama 모델: {}", modelId);
            }
        }

        // Anthropic 설정 검증
        if (anthropic.isEnabled()) {
            log.info("Anthropic 설정: baseUrl={}, 모델 수={}",
                    anthropic.getBaseUrl(), anthropic.getModels().size());
            for (String modelId : anthropic.getModels().keySet()) {
                log.debug("  - Anthropic 모델: {}", modelId);
            }
        }

        // OpenAI 설정 검증
        if (openai.isEnabled()) {
            log.info("OpenAI 설정: baseUrl={}, 모델 수={}",
                    openai.getBaseUrl(), openai.getModels().size());
            for (String modelId : openai.getModels().keySet()) {
                log.debug("  - OpenAI 모델: {}", modelId);
            }
        }

        // 프로바이더 매핑 검증
        log.info("프로바이더 매핑 규칙: {} 개", providerMapping.size());
        for (Map.Entry<String, String> entry : providerMapping.entrySet()) {
            log.debug("  - {} -> {}", entry.getKey(), entry.getValue());
        }

        // Tier 기본값 검증
        log.info("Tier 기본값 설정: {} 개", defaults.getTierDefaults().size());
        for (Map.Entry<Integer, DefaultSpecs.TierDefaults> entry : defaults.getTierDefaults().entrySet()) {
            DefaultSpecs.TierDefaults td = entry.getValue();
            log.debug("  - Tier {}: timeout={}ms, temperature={}, maxTokens={}",
                    entry.getKey(), td.getTimeoutMs(), td.getTemperature(), td.getMaxTokens());
        }

        log.info("모델 제공자 설정 검증 완료");
    }
}