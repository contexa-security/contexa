package io.contexa.contexacore.std.llm.model;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class ModelDescriptor {

    private String modelId;

    private String displayName;

    private String provider;

    private Integer tier;

    private String version;

    private String modelSize;

    @Builder.Default
    private ModelCapabilities capabilities = ModelCapabilities.builder().build();

    @Builder.Default
    private PerformanceProfile performance = PerformanceProfile.builder().build();

    @Builder.Default
    private CostProfile cost = CostProfile.builder().build();

    @Builder.Default
    private ModelOptions options = ModelOptions.builder().build();

    private Map<String, Object> metadata;

    @Builder.Default
    private ModelStatus status = ModelStatus.AVAILABLE;

    @Data
    @Builder
    public static class ModelCapabilities {
        @Builder.Default
        private boolean streaming = true;

        @Builder.Default
        private boolean toolCalling = false;

        @Builder.Default
        private boolean functionCalling = false;

        @Builder.Default
        private boolean vision = false;

        @Builder.Default
        private boolean multiModal = false;

        @Builder.Default
        private int maxTokens = 4096;

        @Builder.Default
        private int contextWindow = 4096;

        @Builder.Default
        private boolean supportsSystemMessage = true;

        @Builder.Default
        private int maxOutputTokens = 4096;
    }

    @Data
    @Builder
    public static class PerformanceProfile {
        
        @Builder.Default
        private Integer latency = 1000;

        @Builder.Default
        private ThroughputLevel throughput = ThroughputLevel.MEDIUM;

        @Builder.Default
        private Integer concurrency = 10;

        @Builder.Default
        private Integer tokensPerSecond = 100;

        @Builder.Default
        private Integer recommendedTimeout = 30000;

        @Builder.Default
        private Double performanceScore = 50.0;
    }

    @Data
    @Builder
    public static class CostProfile {
        
        @Builder.Default
        private Double costPerInputToken = 0.0;

        @Builder.Default
        private Double costPerOutputToken = 0.0;

        @Builder.Default
        private Double costPerRequest = 0.0;

        private Double monthlySubscription;

        @Builder.Default
        private Double costEfficiency = 50.0;
    }

    @Data
    @Builder
    public static class ModelOptions {
        
        @Builder.Default
        private Double temperature = 0.7;

        @Builder.Default
        private Double topP = 0.9;

        private Integer topK;

        @Builder.Default
        private Double repetitionPenalty = 1.0;

        private Integer seed;

        private Map<String, Object> customOptions;
    }

    public enum ThroughputLevel {
        LOW(10),           
        MEDIUM(100),       
        HIGH(1000),        
        VERY_HIGH(10000);  

        private final int maxRequestsPerSecond;

        ThroughputLevel(int maxRequestsPerSecond) {
            this.maxRequestsPerSecond = maxRequestsPerSecond;
        }

        public int getMaxRequestsPerSecond() {
            return maxRequestsPerSecond;
        }
    }

    public enum ModelStatus {
        AVAILABLE,      
        UNAVAILABLE,    
        LOADING,        
        ERROR,          
        MAINTENANCE,    
        DEPRECATED      
    }

    public boolean isSuitableForTier(int tier) {
        return this.tier != null && this.tier == tier;
    }

    public boolean isFastResponse() {
        return performance != null &&
               performance.getLatency() != null &&
               performance.getLatency() < 100;
    }

    public boolean isCostEffective() {
        if (cost == null) return true; 

        return (cost.getCostPerInputToken() == 0.0 && cost.getCostPerOutputToken() == 0.0) ||
               (cost.getCostEfficiency() != null && cost.getCostEfficiency() > 70);
    }

    public boolean supportsAdvancedFeatures() {
        return capabilities != null &&
               (capabilities.isToolCalling() ||
                capabilities.isFunctionCalling() ||
                capabilities.isMultiModal());
    }
}