package io.contexa.contexacore.config;

import io.contexa.contexacore.std.llm.exception.ModelSelectionException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

/**
 * 2-Tier LLM 시스템 설정 프로퍼티
 * application-llm.yml의 설정을 매핑
 *
 * AI Native v6.7: L1 = L2 프롬프트, 차이점은 LLM 모델만
 * - Layer1: 경량 로컬 모델 (95% 트래픽)
 * - Layer2: 고성능 클라우드 모델 (5% 트래픽, ESCALATE 시)
 */
@Slf4j
@Data
@ConfigurationProperties(prefix = "spring.ai.security")
public class TieredLLMProperties {

    // 기본 모델 상수
//    public static final String DEFAULT_LAYER1_MODEL = "llama3.1:8b";
    public static final String DEFAULT_LAYER1_MODEL = "qwen2.5:14b";
    public static final String DEFAULT_LAYER2_MODEL = "exaone3.5:latest";

    @Autowired(required = false)
    private ModelProviderProperties modelProviderProperties;

    /**
     * Layer 1 모델 설정 (경량 로컬 모델)
     * 기본값: llama3.1:8b
     */
    @NestedConfigurationProperty
    private LayerConfig layer1 = new LayerConfig();

    /**
     * Layer 2 모델 설정 (고성능 클라우드 모델)
     * 기본값: claude-3-5-sonnet-20241022
     */
    @NestedConfigurationProperty
    private LayerConfig layer2 = new LayerConfig();


    /**
     * 2-Tier 시스템 상세 설정
     */
    @NestedConfigurationProperty
    private TieredConfig tiered = new TieredConfig();

    /**
     * 레이어별 모델 설정
     */
    @Data
    public static class LayerConfig {
        private String model;
        private BackupConfig backup;

        @Data
        public static class BackupConfig {
            private String model;
        }

        /**
         * 백업 모델 포함 모델명 반환
         */
        public String getModelWithFallback() {
            if (backup != null && backup.getModel() != null) {
                return model; // 기본 모델 먼저 시도
            }
            return model;
        }

        /**
         * 백업 모델 존재 여부
         */
        public boolean hasBackupModel() {
            return backup != null && backup.getModel() != null;
        }
    }

    /**
     * 2-Tier 시스템 상세 설정
     */
    @Data
    public static class TieredConfig {
        private boolean enabled = true;

        /**
         * 트래픽 분배 설정
         */
        @NestedConfigurationProperty
        private TrafficDistribution trafficDistribution = new TrafficDistribution();

        /**
         * Layer 1 상세 설정
         */
        @NestedConfigurationProperty
        private LayerDetails layer1 = new LayerDetails();

        /**
         * Layer 2 상세 설정
         */
        @NestedConfigurationProperty
        private LayerDetails layer2 = new LayerDetails();


        /**
         * 적응형 라우팅 설정
         */
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

            /**
             * 기본 Temperature 값 반환 (2-Tier 시스템)
             */
            public Double getDefaultTemperature(int tier) {
                return switch (tier) {
                    case 1 -> 0.3;  // Layer 1: 경량 모델 (낮은 창의성, 빠른 응답)
                    case 2 -> 0.7;  // Layer 2: 고성능 모델 (높은 창의성, 심층 분석)
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

    /**
     * tier에 따른 모델명 반환 (유효성 검증 포함)
     */
    public String getModelNameForTier(int tier) {
        validateTier(tier);

        String modelName = switch (tier) {
            case 1 -> layer1 != null ? layer1.getModel() : null;
            case 2 -> layer2 != null ? layer2.getModel() : null;
            default -> layer1 != null ? layer1.getModel() : null; // 기본값은 Layer 1
        };

        if (modelName == null || modelName.trim().isEmpty()) {
            log.warn("Tier {}에 대한 모델이 설정되지 않았습니다. 런타임 폴백 전략을 사용합니다", tier);
            // 예외를 던지지 않고 null을 반환하여 폴백 전략이 작동하도록 함
            return null;
        }

        return modelName.trim();
    }

    /**
     * tier에 따른 백업 모델명 반환 (유효성 검증 포함)
     */
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
                log.debug("Tier {}의 백업 모델: {}", tier, backupModel);
                return backupModel.trim();
            }
        }

        log.debug("Tier {}에 백업 모델이 설정되지 않았습니다", tier);
        return null;
    }

    /**
     * tier에 따른 타임아웃 반환 (유효성 검증 포함)
     */
    public Integer getTimeoutForTier(int tier) {
        validateTier(tier);

        Integer timeout = switch (tier) {
            case 1 -> tiered.getLayer1().getTimeoutMs();
            case 2 -> tiered.getLayer2().getTimeoutMs();
            default -> 1000; // 기본값 1초
        };

        // 타임아웃 값 유효성 검증
        if (timeout == null || timeout <= 0) {
            log.warn("유효하지 않은 타임아웃 값: {} (tier: {}), 기본값 사용", timeout, tier);
            return getDefaultTimeoutForTier(tier);
        }

        // 최대 타임아웃 제한 (30초)
        if (timeout > 30000) {
            log.warn("타임아웃이 너무 깁니다: {}ms (tier: {}), 30초로 제한", timeout, tier);
            return 30000;
        }

        return timeout;
    }

    /**
     * tier에 따른 기본 Temperature 반환 (유효성 검증 포함)
     */
    public Double getTemperatureForTier(int tier) {
        validateTier(tier);

        Double temperature = switch (tier) {
            case 1 -> tiered.getLayer1().getDefaultTemperature(1);
            case 2 -> tiered.getLayer2().getDefaultTemperature(2);
            default -> 0.5;
        };

        // Temperature 값 유효성 검증 (0.0 ~ 1.0)
        if (temperature == null || temperature < 0.0 || temperature > 1.0) {
            log.warn("유효하지 않은 temperature 값: {} (tier: {}), 기본값 사용", temperature, tier);
            return getDefaultTemperatureForTier(tier);
        }

        return temperature;
    }

    /**
     * 모델이 Ollama 모델인지 확인
     */
    public boolean isOllamaModel(String modelName) {
        if (modelName == null) return false;

        // ModelProviderProperties를 사용하여 판별
        if (modelProviderProperties != null) {
            String provider = modelProviderProperties.getProviderForModel(modelName);
            return "ollama".equals(provider);
        }

        // 폴백: 기본 패턴 매칭 (ModelProviderProperties가 없는 경우)
        return modelName.contains(":") ||
               modelName.startsWith("llama") ||
               modelName.startsWith("tinyllama") ||
               modelName.startsWith("mistral") ||
               modelName.startsWith("phi") ||
               modelName.startsWith("qwen");
    }

    /**
     * 모델이 클라우드 모델인지 확인
     */
    public boolean isCloudModel(String modelName) {
        if (modelName == null) return false;

        // ModelProviderProperties를 사용하여 판별
        if (modelProviderProperties != null) {
            String provider = modelProviderProperties.getProviderForModel(modelName);
            return "anthropic".equals(provider) || "openai".equals(provider);
        }

        // 폴백: 기본 패턴 매칭
        return modelName.startsWith("claude") ||
               modelName.startsWith("gpt") ||
               modelName.startsWith("anthropic") ||
               modelName.startsWith("openai");
    }

    /**
     * Tier 값 유효성 검증 (2-Tier 시스템)
     */
    private void validateTier(int tier) {
        if (tier < 1 || tier > 2) {
            throw new ModelSelectionException("유효하지 않은 tier 값: " + tier + " (1-2 사이여야 함)", tier);
        }
    }

    /**
     * Tier별 기본 타임아웃 값
     */
    private Integer getDefaultTimeoutForTier(int tier) {
        // ModelProviderProperties에서 기본값 가져오기 시도
        if (modelProviderProperties != null) {
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
                modelProviderProperties.getTierDefaults(tier);
            if (tierDefaults != null && tierDefaults.getTimeoutMs() != null) {
                return tierDefaults.getTimeoutMs();
            }
        }

        // 폴백: 하드코딩된 기본값 (2-Tier 시스템)
        return switch (tier) {
            case 1 -> 100;     // Layer 1: 경량 모델 (빠른 응답)
            case 2 -> 5000;    // Layer 2: 고성능 모델 (심층 분석)
            default -> 1000;   // 기본값
        };
    }

    /**
     * Tier별 기본 Temperature 값 (2-Tier 시스템)
     */
    private Double getDefaultTemperatureForTier(int tier) {
        // ModelProviderProperties에서 기본값 가져오기 시도
        if (modelProviderProperties != null) {
            ModelProviderProperties.DefaultSpecs.TierDefaults tierDefaults =
                modelProviderProperties.getTierDefaults(tier);
            if (tierDefaults != null && tierDefaults.getTemperature() != null) {
                return tierDefaults.getTemperature();
            }
        }

        // 폴백: 하드코딩된 기본값 (2-Tier 시스템)
        return switch (tier) {
            case 1 -> 0.3;    // Layer 1: 경량 모델 (낮은 창의성, 빠른 응답)
            case 2 -> 0.7;    // Layer 2: 고성능 모델 (높은 창의성, 심층 분석)
            default -> 0.5;   // 기본값
        };
    }

    /**
     * 설정 초기화 후 유효성 검증 및 기본값 적용 (2-Tier 시스템)
     */
    @PostConstruct
    public void validateConfiguration() {
        log.info("2-Tier LLM 시스템 설정 검증 시작");

        // 기본값 적용
        applyDefaultModels();

        // 실제 로드된 설정값들 디버그 출력
        log.info("=== 실제 로드된 설정값 디버그 ===");
        log.info("layer1: {}", layer1);
        log.info("layer1.model: {}", layer1 != null ? layer1.getModel() : "null");
        log.info("layer2: {}", layer2);
        log.info("layer2.model: {}", layer2 != null ? layer2.getModel() : "null");
        log.info("tiered: {}", tiered);
        log.info("================================");

        // 필수 모델 설정 확인 (2-Tier)
        validateLayerConfig(1, layer1);
        validateLayerConfig(2, layer2);

        // 트래픽 분배 비율 검증
        validateTrafficDistribution();

        log.info("2-Tier LLM 시스템 설정 검증 완료");
    }

    /**
     * 기본 모델 설정 적용
     * application.yml에서 설정하지 않은 경우 기본값 사용
     */
    private void applyDefaultModels() {
        // Layer 1 기본값 적용
        if (layer1 == null) {
            layer1 = new LayerConfig();
        }
        if (layer1.getModel() == null || layer1.getModel().trim().isEmpty()) {
            layer1.setModel(DEFAULT_LAYER1_MODEL);
            log.info("Layer 1 기본 모델 적용: {}", DEFAULT_LAYER1_MODEL);
        }

        // Layer 2 기본값 적용
        if (layer2 == null) {
            layer2 = new LayerConfig();
        }
        if (layer2.getModel() == null || layer2.getModel().trim().isEmpty()) {
            layer2.setModel(DEFAULT_LAYER2_MODEL);
            log.info("Layer 2 기본 모델 적용: {}", DEFAULT_LAYER2_MODEL);
        }
    }

    /**
     * 레이어 설정 검증
     */
    private void validateLayerConfig(int tier, LayerConfig config) {
        if (config == null) {
            log.warn("Layer {} 설정이 없습니다. 런타임에 폴백 전략을 사용합니다", tier);
            return;
        }

        if (config.getModel() == null || config.getModel().trim().isEmpty()) {
            log.warn("Layer {}의 모델이 설정되지 않았습니다. 런타임에 폴백 전략을 사용합니다", tier);
            return;
        }

        log.info("Layer {} 설정 확인: model={}, backup={}",
                tier, config.getModel(),
                config.hasBackupModel() ? config.getBackup().getModel() : "없음");
    }

    /**
     * 트래픽 분배 비율 검증 (2-Tier 시스템)
     */
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

        log.info("트래픽 분배 비율: Layer1={}%, Layer2={}%",
                dist.getLayer1Percentage(),
                dist.getLayer2Percentage());
    }
}