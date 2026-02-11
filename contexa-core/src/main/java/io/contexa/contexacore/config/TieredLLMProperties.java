package io.contexa.contexacore.config;

import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Data
@ConfigurationProperties(prefix = "spring.ai.security")
public class TieredLLMProperties {

    public static final String DEFAULT_LAYER1_MODEL = "qwen2.5:14b";
    public static final String DEFAULT_LAYER2_MODEL = "exaone3.5:latest";
    public static final String DEFAULT_PROVIDER_PRIORITY = "ollama,anthropic,openai";

    private String providerPriority = DEFAULT_PROVIDER_PRIORITY;

    @NestedConfigurationProperty
    private LayerConfig layer1 = new LayerConfig();

    @NestedConfigurationProperty
    private LayerConfig layer2 = new LayerConfig();

    @NestedConfigurationProperty
    private TieredConfig tiered = new TieredConfig();

    @Data
    public static class LayerConfig {
        private String model;
        private BackupConfig backup;

        @Data
        public static class BackupConfig {
            private String model;
        }

        public String getModelWithFallback() {
            if (backup != null && backup.getModel() != null) {
                return model;
            }
            return model;
        }

        public boolean hasBackupModel() {
            return backup != null && backup.getModel() != null;
        }
    }

    @Data
    public static class TieredConfig {
        private boolean enabled = true;

        @NestedConfigurationProperty
        private TrafficDistribution trafficDistribution = new TrafficDistribution();

        @NestedConfigurationProperty
        private LayerDetails layer1 = new LayerDetails();

        @NestedConfigurationProperty
        private LayerDetails layer2 = new LayerDetails();

        @NestedConfigurationProperty
        private AdaptiveConfig adaptive = new AdaptiveConfig();

        @Data
        public static class TrafficDistribution {
            private double layer1Percentage = 95.0;
            private double layer2Percentage = 5.0;
        }

        @Data
        public static class LayerDetails {
            private boolean enabled = true;
            private Integer timeoutMs;
            private Integer cacheTtlSeconds;
            private Double embeddingSimilarityThreshold;
            private Integer contextWindowMinutes;
            private Integer vectorSearchLimit;
            private Integer behaviorBaselineDays;
            private boolean enableSoar;
            private Double autoExecuteThreshold;

            public Double getDefaultTemperature(int tier) {
                return switch (tier) {
                    case 1 -> 0.3;
                    case 2 -> 0.7;
                    default -> 0.5;
                };
            }
        }

        @Data
        public static class AdaptiveConfig {
            private boolean enabled = true;
            private double learningRate = 0.01;
            private int peakHoursStart = 9;
            private int peakHoursEnd = 18;
        }
    }

    public String getModelNameForTier(int tier) {
        validateTier(tier);

        String modelName = switch (tier) {
            case 1 -> layer1 != null ? layer1.getModel() : null;
            case 2 -> layer2 != null ? layer2.getModel() : null;
            default -> layer1 != null ? layer1.getModel() : null;
        };

        if (modelName == null || modelName.trim().isEmpty()) {
            log.debug("Model for Tier {} is not configured. Will use provider default model (auto-inheritance)", tier);
            return null;
        }

        return modelName.trim();
    }

    public String getBackupModelNameForTier(int tier) {
        validateTier(tier);

        LayerConfig config = switch (tier) {
            case 1 -> layer1;
            case 2 -> layer2;
            default -> null;
        };

        if (config != null && config.hasBackupModel()) {
            String backupModel = config.getBackup().getModel();
            if (backupModel != null && !backupModel.trim().isEmpty()) {
                return backupModel.trim();
            }
        }

        return null;
    }

    public Integer getTimeoutForTier(int tier) {
        validateTier(tier);

        Integer timeout = switch (tier) {
            case 1 -> tiered.getLayer1().getTimeoutMs();
            case 2 -> tiered.getLayer2().getTimeoutMs();
            default -> 1000;
        };

        if (timeout == null || timeout <= 0) {
            log.warn("Invalid timeout value: {} (tier: {}), using default", timeout, tier);
            return getDefaultTimeoutForTier(tier);
        }

        if (timeout > 30000) {
            log.warn("Timeout is too long: {}ms (tier: {}), limiting to 30s", timeout, tier);
            return 30000;
        }

        return timeout;
    }

    public Double getTemperatureForTier(int tier) {
        validateTier(tier);

        Double temperature = switch (tier) {
            case 1 -> tiered.getLayer1().getDefaultTemperature(1);
            case 2 -> tiered.getLayer2().getDefaultTemperature(2);
            default -> 0.5;
        };

        if (temperature == null || temperature < 0.0 || temperature > 1.0) {
            log.warn("Invalid temperature value: {} (tier: {}), using default", temperature, tier);
            return getDefaultTemperatureForTier(tier);
        }

        return temperature;
    }

    public boolean isOllamaModel(String modelName) {
        if (modelName == null)
            return false;

        String lowerName = modelName.toLowerCase();
        return lowerName.contains(":") ||
                lowerName.contains("llama") ||
                lowerName.contains("qwen") ||
                lowerName.contains("mistral") ||
                lowerName.contains("phi") ||
                lowerName.contains("gemma") ||
                lowerName.contains("exaone") ||
                lowerName.contains("deepseek");
    }

    public boolean isCloudModel(String modelName) {
        if (modelName == null)
            return false;

        String lowerName = modelName.toLowerCase();
        return lowerName.contains("claude") ||
                lowerName.contains("gpt") ||
                lowerName.contains("anthropic") ||
                lowerName.contains("openai") ||
                lowerName.contains("o1");
    }

    /**
     * Returns provider priority configuration as a List.
     * Priority setting determines the order of model selection.
     *
     * @return List of provider priorities
     */
    public List<String> getProviderPriorityList() {
        if (providerPriority == null || providerPriority.trim().isEmpty()) {
            return Arrays.asList(DEFAULT_PROVIDER_PRIORITY.split(","));
        }
        return Arrays.stream(providerPriority.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private void validateTier(int tier) {
        if (tier < 1 || tier > 2) {
            throw new ModelSelectionException("Invalid tier value: " + tier + " (must be 1-2)", tier);
        }
    }

    private Integer getDefaultTimeoutForTier(int tier) {
        return switch (tier) {
            case 1 -> 100;
            case 2 -> 5000;
            default -> 1000;
        };
    }

    private Double getDefaultTemperatureForTier(int tier) {
        return switch (tier) {
            case 1 -> 0.3;
            case 2 -> 0.7;
            default -> 0.5;
        };
    }

    @PostConstruct
    public void validateConfiguration() {
        applyDefaultModels();
        validateLayerConfig(1, layer1);
        validateLayerConfig(2, layer2);
        validateTrafficDistribution();
    }

    private void applyDefaultModels() {
        // Auto-inheritance: Do not apply default values
        // When layer model is not set, provider default model (primaryChatModel) will be used automatically
        if (layer1 == null) {
            layer1 = new LayerConfig();
        }

        if (layer2 == null) {
            layer2 = new LayerConfig();
        }
        // Keep null when model is not set -> DynamicModelSelectionStrategy will use primaryChatModel
    }

    private void validateLayerConfig(int tier, LayerConfig config) {
        if (config == null) {
            log.info("Layer {} configuration missing. Will use provider default model (auto-inheritance)", tier);
            return;
        }

        if (config.getModel() == null || config.getModel().trim().isEmpty()) {
            log.info("Layer {} model not configured. Will use provider default model (auto-inheritance)", tier);
            return;
        }
    }

    private void validateTrafficDistribution() {
        if (tiered == null || tiered.getTrafficDistribution() == null) {
            log.warn("Traffic distribution configuration missing. Using defaults (Layer1=95%, Layer2=5%)");
            return;
        }

        TieredConfig.TrafficDistribution dist = tiered.getTrafficDistribution();
        double total = dist.getLayer1Percentage() + dist.getLayer2Percentage();

        if (Math.abs(total - 100.0) > 0.01) {
            log.warn("Traffic distribution total is not 100%: {}%", total);
        }
    }
}
