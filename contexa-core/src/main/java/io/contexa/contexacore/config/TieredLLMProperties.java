package io.contexa.contexacore.config;

import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

@Slf4j
@Data
@ConfigurationProperties(prefix = "spring.ai.security")
public class TieredLLMProperties {

    public static final String DEFAULT_LAYER1_MODEL = "qwen2.5:14b";
    public static final String DEFAULT_LAYER2_MODEL = "exaone3.5:latest";

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

        public boolean hasBackupModel() {
            return backup != null && backup.getModel() != null;
        }
    }

    @Data
    public static class TieredConfig {

        @NestedConfigurationProperty
        private LayerDetails layer1 = new LayerDetails();

        @NestedConfigurationProperty
        private LayerDetails layer2 = new LayerDetails();

        @Data
        public static class LayerDetails {
            private Integer timeoutMs;

            public Double getDefaultTemperature(int tier) {
                return switch (tier) {
                    case 1 -> 0.3;
                    case 2 -> 0.7;
                    default -> 0.5;
                };
            }
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
            return getDefaultTimeoutForTier(tier);
        }

        if (timeout > 120000) {
            log.error("Timeout exceeds maximum: {}ms (tier: {}), limiting to 120s", timeout, tier);
            return 120000;
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
            log.error("Invalid temperature value: {} (tier: {}), using default", temperature, tier);
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

    private void validateTier(int tier) {
        if (tier < 1 || tier > 2) {
            throw new ModelSelectionException("Invalid tier value: " + tier + " (must be 1-2)", tier);
        }
    }

    private Integer getDefaultTimeoutForTier(int tier) {
        return switch (tier) {
            case 1 -> 30000;
            case 2 -> 60000;
            default -> 30000;
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
        if (layer1 == null) {
            layer1 = new LayerConfig();
        }
        if (layer2 == null) {
            layer2 = new LayerConfig();
        }
    }
}
