package io.contexa.contexacoreenterprise.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Security Evaluator 설정
 */
@Data
@ConfigurationProperties(prefix = "security.evaluator")
public class SecurityEvaluatorProperties {

    /**
     * Consensus 설정
     */
    @NestedConfigurationProperty
    private ConsensusSettings consensus = new ConsensusSettings();

    /**
     * 최소 전략 수
     */
    private int minStrategies = 3;

    /**
     * 타임아웃 (밀리초)
     */
    private int timeoutMs = 500;

    /**
     * 병렬 처리 활성화 여부
     */
    private boolean parallelEnabled = true;

    /**
     * 가중치 설정
     */
    @NestedConfigurationProperty
    private WeightSettings weight = new WeightSettings();

    /**
     * Consensus 설정
     */
    @Data
    public static class ConsensusSettings {
        private double threshold = 0.75;
    }

    /**
     * 가중치 설정
     */
    @Data
    public static class WeightSettings {
        private double behavioral = 0.3;
        private double mitre = 0.2;
        private double nist = 0.1;
    }
}
