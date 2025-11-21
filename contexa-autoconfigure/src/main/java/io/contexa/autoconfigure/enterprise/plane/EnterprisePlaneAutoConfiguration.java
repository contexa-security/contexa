package io.contexa.autoconfigure.enterprise.plane;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacoreenterprise.plane.service.SignalInconsistencyDetector;
import io.contexa.contexacoreenterprise.plane.service.SensitiveResourceService;
import io.contexa.contexacoreenterprise.plane.service.HoneypotPatternAnalyzer;
import io.contexa.contexacoreenterprise.plane.service.ColdPathCapacityManager;
import io.contexa.contexacoreenterprise.plane.service.AttackModeHysteresisManager;
import io.contexa.contexacoreenterprise.plane.service.AntiEvasionSamplingEngine;
import io.contexa.contexacoreenterprise.plane.service.AdaptiveThresholdSystem;
import io.contexa.contexacoreenterprise.plane.service.AccumulatedRiskCalculator;
import io.contexa.contexacoreenterprise.plane.ZeroTrustHotPathOrchestratorImpl;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Enterprise Plane AutoConfiguration
 *
 * Contexa Enterprise 모듈의 Zero Trust HOT Path Plane 자동 구성을 제공합니다.
 * @Bean 방식으로 Enterprise Plane 서비스들을 명시적으로 등록합니다.
 *
 * 포함된 컴포넌트 (9개):
 * Zero Trust HOT Path Services (8개):
 * - SignalInconsistencyDetector, SensitiveResourceService
 * - HoneypotPatternAnalyzer, ColdPathCapacityManager
 * - AttackModeHysteresisManager, AntiEvasionSamplingEngine
 * - AdaptiveThresholdSystem, AccumulatedRiskCalculator
 *
 * Orchestrator (1개):
 * - ZeroTrustHotPathOrchestratorImpl
 *
 * 활성화 조건:
 * contexa:
 *   enterprise:
 *     enabled: true
 *   plane:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.enterprise",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
public class EnterprisePlaneAutoConfiguration {

    public EnterprisePlaneAutoConfiguration() {
        // @Bean 방식으로 Enterprise Plane 서비스 등록
    }

    // ========== Zero Trust HOT Path Services (8개) ==========

    /**
     * 1. SignalInconsistencyDetector - 신호 불일치 탐지기 (Mahalanobis Distance)
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SignalInconsistencyDetector signalInconsistencyDetector() {
        return new SignalInconsistencyDetector();
    }

    /**
     * 2. SensitiveResourceService - 민감 리소스 탐지 서비스 (@Protectable 기반)
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SensitiveResourceService sensitiveResourceService() {
        return new SensitiveResourceService();
    }

    /**
     * 3. HoneypotPatternAnalyzer - Honeypot 패턴 분석기 (Phase 1)
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public HoneypotPatternAnalyzer honeypotPatternAnalyzer() {
        return new HoneypotPatternAnalyzer();
    }

    /**
     * 4. ColdPathCapacityManager - Cold Path 용량 관리 시스템
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ColdPathCapacityManager coldPathCapacityManager() {
        return new ColdPathCapacityManager();
    }

    /**
     * 5. AttackModeHysteresisManager - 공격 모드 히스테리시스 관리자
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AttackModeHysteresisManager attackModeHysteresisManager() {
        return new AttackModeHysteresisManager();
    }

    /**
     * 6. AntiEvasionSamplingEngine - Anti-Evasion 샘플링 엔진
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AntiEvasionSamplingEngine antiEvasionSamplingEngine() {
        return new AntiEvasionSamplingEngine();
    }

    /**
     * 7. AdaptiveThresholdSystem - 적응형 임계값 시스템 (CUSUM 기반)
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AdaptiveThresholdSystem adaptiveThresholdSystem() {
        return new AdaptiveThresholdSystem();
    }

    /**
     * 8. AccumulatedRiskCalculator - 누적 위험 계산기 (7-Signal 기반)
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public AccumulatedRiskCalculator accumulatedRiskCalculator() {
        return new AccumulatedRiskCalculator();
    }

    // ========== Orchestrator (1개) ==========

    /**
     * 9. ZeroTrustHotPathOrchestratorImpl - Zero Trust HOT Path 오케스트레이터
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.plane",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ZeroTrustHotPathOrchestratorImpl zeroTrustHotPathOrchestratorImpl() {
        return new ZeroTrustHotPathOrchestratorImpl();
    }
}
