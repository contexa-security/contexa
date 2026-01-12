package io.contexa.contexacore.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Security Cold Path 설정
 */
@Data
@ConfigurationProperties(prefix = "security.coldpath")
public class SecurityColdPathProperties {

    /**
     * 신뢰도 설정
     */
    @NestedConfigurationProperty
    private ConfidenceSettings confidence = new ConfidenceSettings();

    /**
     * 신뢰도 설정 (2-Tier 시스템)
     */
    @Data
    public static class ConfidenceSettings {
        private double layer1Base = 0.5;
        private double layer2Base = 0.7;  // Layer 2가 최상위 계층 (2-Tier 시스템)
    }
}
