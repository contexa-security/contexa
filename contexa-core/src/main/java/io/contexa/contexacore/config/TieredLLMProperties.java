package io.contexa.contexacore.config;

import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${spring.ai.chat.model.priority:" + DEFAULT_PROVIDER_PRIORITY + "}")
    private String providerPriority;

    @Autowired(required = false)
    private ModelProviderProperties modelProviderProperties;

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
            log.warn("Tier {}에 대한 모델이 설정되지 않았습니다. 런타임 폴백 전략을 사용합니다", tier);
            
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
            log.warn("유효하지 않은 타임아웃 값: {} (tier: {}), 기본값 사용", timeout, tier);
            return getDefaultTimeoutForTier(tier);
        }

        if (timeout > 30000) {
            log.warn("타임아웃이 너무 깁니다: {}ms (tier: {}), 30초로 제한", timeout, tier);
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
            log.warn("유효하지 않은 temperature 값: {} (tier: {}), 기본값 사용", temperature, tier);
            return getDefaultTemperatureForTier(tier);
        }

        return temperature;
    }

    public boolean isOllamaModel(String modelName) {
        if (modelName == null) return false;

        if (modelProviderProperties != null) {
            String provider = modelProviderProperties.getProviderForModel(modelName);
            return "ollama".equals(provider);
        }

        return modelName.contains(":") ||
               modelName.startsWith("llama") ||
               modelName.startsWith("tinyllama") ||
               modelName.startsWith("mistral") ||
               modelName.startsWith("phi") ||
               modelName.startsWith("qwen");
    }

    public boolean isCloudModel(String modelName) {
        if (modelName == null) return false;

        if (modelProviderProperties != null) {
            String provider = modelProviderProperties.getProviderForModel(modelName);
            return "anthropic".equals(provider) || "openai".equals(provider);
        }

        return modelName.startsWith("claude") ||
               modelName.startsWith("gpt") ||
               modelName.startsWith("anthropic") ||
               modelName.startsWith("openai");
    }

    /**
     * Provider priority 설정을 List로 반환합니다.
     * priority 설정에 따라 모델 선택 시 우선순위가 결정됩니다.
     *
     * @return 프로바이더 우선순위 목록
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
            throw new ModelSelectionException("유효하지 않은 tier 값: " + tier + " (1-2 사이여야 함)", tier);
        }
    }

    private Integer getDefaultTimeoutForTier(int tier) {
        
        if (modelProviderProperties != null) {
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
                modelProviderProperties.getTierDefaults(tier);
            if (tierDefaults != null && tierDefaults.getTimeoutMs() != null) {
                return tierDefaults.getTimeoutMs();
            }
        }

        return switch (tier) {
            case 1 -> 100;     
            case 2 -> 5000;    
            default -> 1000;   
        };
    }

    private Double getDefaultTemperatureForTier(int tier) {
        
        if (modelProviderProperties != null) {
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
                modelProviderProperties.getTierDefaults(tier);
            if (tierDefaults != null && tierDefaults.getTemperature() != null) {
                return tierDefaults.getTemperature();
            }
        }

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
        
        if (layer1 == null) {
            layer1 = new LayerConfig();
        }
        if (layer1.getModel() == null || layer1.getModel().trim().isEmpty()) {
            layer1.setModel(DEFAULT_LAYER1_MODEL);
                    }

        if (layer2 == null) {
            layer2 = new LayerConfig();
        }
        if (layer2.getModel() == null || layer2.getModel().trim().isEmpty()) {
            layer2.setModel(DEFAULT_LAYER2_MODEL);
                    }
    }

    private void validateLayerConfig(int tier, LayerConfig config) {
        if (config == null) {
            log.warn("Layer {} 설정이 없습니다. 런타임에 폴백 전략을 사용합니다", tier);
            return;
        }

        if (config.getModel() == null || config.getModel().trim().isEmpty()) {
            log.warn("Layer {}의 모델이 설정되지 않았습니다. 런타임에 폴백 전략을 사용합니다", tier);
            return;
        }

            }

    private void validateTrafficDistribution() {
        if (tiered == null || tiered.getTrafficDistribution() == null) {
            log.warn("트래픽 분배 설정이 없습니다. 기본값 사용 (Layer1=95%, Layer2=5%)");
            return;
        }

        TieredConfig.TrafficDistribution dist = tiered.getTrafficDistribution();
        double total = dist.getLayer1Percentage() + dist.getLayer2Percentage();

        if (Math.abs(total - 100.0) > 0.01) {
            log.warn("트래픽 분배 비율 합계가 100%가 아닙니다: {}%", total);
        }

            }
}