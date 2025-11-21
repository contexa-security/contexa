package io.contexa.autoconfigure.enterprise.dashboard;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.repository.SoarIncidentRepository;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.UserTrustMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.HCADFeedbackLoopMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.EventPublishingMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.DefaultRoutingDecisionMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.vectorstore.VectorStoreMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.unified.UnifiedSecurityMetricsCollector;
import io.contexa.contexacoreenterprise.dashboard.metrics.unified.SystemMetricsCollector;
import io.contexa.contexacoreenterprise.dashboard.metrics.soar.ToolExecutionMetrics;
import io.contexa.contexacoreenterprise.dashboard.metrics.plane.OrthogonalSignalCollector;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Enterprise Dashboard AutoConfiguration
 *
 * Contexa Enterprise 모듈의 Dashboard Metrics 자동 구성을 제공합니다.
 * @Bean 방식으로 Dashboard Metrics 서비스들을 명시적으로 등록합니다.
 *
 * 포함된 컴포넌트 (10개):
 * Zero Trust Metrics (4개):
 * - UserTrustMetrics, HCADFeedbackLoopMetrics, EventPublishingMetrics, DefaultRoutingDecisionMetrics
 *
 * Vector Store Metrics (1개):
 * - VectorStoreMetrics
 *
 * Unified Metrics (2개):
 * - UnifiedSecurityMetricsCollector, SystemMetricsCollector
 *
 * SOAR Metrics (1개):
 * - ToolExecutionMetrics
 *
 * Plane Metrics (1개):
 * - OrthogonalSignalCollector
 *
 * Evolution Metrics (1개):
 * - EvolutionMetricsCollector
 *
 * 활성화 조건:
 * contexa:
 *   enterprise:
 *     enabled: true
 *   dashboard:
 *     metrics:
 *       enabled: true  (기본값)
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
public class EnterpriseDashboardAutoConfiguration {

    public EnterpriseDashboardAutoConfiguration() {
        // @Bean 방식으로 Enterprise Dashboard Metrics 서비스 등록
    }

    // ========== Zero Trust Metrics (4개) ==========

    /**
     * 1. UserTrustMetrics - 사용자 신뢰도 메트릭
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public UserTrustMetrics userTrustMetrics(MeterRegistry registry) {
        return new UserTrustMetrics(registry);
    }

    /**
     * 2. HCADFeedbackLoopMetrics - HCAD 피드백 루프 메트릭
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public HCADFeedbackLoopMetrics hcadFeedbackLoopMetrics(MeterRegistry registry) {
        return new HCADFeedbackLoopMetrics(registry);
    }

    /**
     * 3. EventPublishingMetrics - 이벤트 발행 메트릭
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public EventPublishingMetrics eventPublishingMetrics(MeterRegistry registry) {
        return new EventPublishingMetrics(registry);
    }

    /**
     * 4. DefaultRoutingDecisionMetrics - 라우팅 결정 메트릭
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public DefaultRoutingDecisionMetrics defaultRoutingDecisionMetrics(MeterRegistry registry) {
        return new DefaultRoutingDecisionMetrics(registry);
    }

    // ========== Vector Store Metrics (1개) ==========

    /**
     * 5. VectorStoreMetrics - 벡터 저장소 메트릭
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public VectorStoreMetrics vectorStoreMetrics() {
        return new VectorStoreMetrics();
    }

    // ========== Unified Metrics (2개) ==========

    /**
     * 6. UnifiedSecurityMetricsCollector - 통합 보안 메트릭 수집기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public UnifiedSecurityMetricsCollector unifiedSecurityMetricsCollector(MeterRegistry registry) {
        return new UnifiedSecurityMetricsCollector(registry);
    }

    /**
     * 7. SystemMetricsCollector - 시스템 메트릭 수집기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public SystemMetricsCollector systemMetricsCollector(
            SoarIncidentRepository incidentRepository,
            @Autowired(required = false) MeterRegistry registry) {
        return new SystemMetricsCollector(incidentRepository, registry);
    }

    // ========== SOAR Metrics (1개) ==========

    /**
     * 8. ToolExecutionMetrics - 도구 실행 메트릭
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public ToolExecutionMetrics toolExecutionMetrics(MeterRegistry registry) {
        return new ToolExecutionMetrics(registry);
    }

    // ========== Plane Metrics (1개) ==========

    /**
     * 9. OrthogonalSignalCollector - 직교 신호 수집기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public OrthogonalSignalCollector orthogonalSignalCollector() {
        return new OrthogonalSignalCollector();
    }

    // ========== Evolution Metrics (1개) ==========

    /**
     * 10. EvolutionMetricsCollector - 진화 메트릭 수집기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(
        prefix = "contexa.dashboard.metrics",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    public EvolutionMetricsCollector evolutionMetricsCollector(
            MeterRegistry registry,
            UnifiedSecurityMetricsCollector unifiedMetrics) {
        return new EvolutionMetricsCollector(registry, unifiedMetrics);
    }
}
