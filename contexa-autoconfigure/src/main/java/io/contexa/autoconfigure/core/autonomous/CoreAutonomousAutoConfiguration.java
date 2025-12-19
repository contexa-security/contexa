package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.config.SecurityPlaneConfiguration;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.strategy.DynamicStrategySelector;
import io.contexa.contexacore.autonomous.tiered.TieredEventProcessor;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.detection.MaliciousPatternDetector;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1FastFilterStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer3ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.template.Layer1PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.template.Layer2PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.template.Layer3PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.*;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.std.rag.processors.ThreatCorrelator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * Core Autonomous AutoConfiguration
 *
 * Contexa 프레임워크의 Autonomous Security Plane 자동 구성을 제공합니다.
 * @Bean 방식으로 Autonomous 관련 컴포넌트들을 명시적으로 등록합니다.
 *
 * 포함된 Configuration:
 * - SecurityPlaneConfiguration - Security Plane 기본 설정
 *
 * 포함된 컴포넌트 (26개):
 * - Level 1: 독립적 서비스 (5개)
 * - Level 2: Level 1 의존 (3개)
 * - Level 3: 독립적/선택적 의존 (9개)
 * - Level 4: Level 3 의존 (3개)
 * - Level 5: Level 4 의존 (5개)
 * - Level 6: SecurityPlaneAgent (1개)
 *
 * 활성화 조건:
 * contexa:
 *   autonomous:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@AutoConfigureAfter(CoreHCADAutoConfiguration.class)
@ConditionalOnProperty(
    prefix = "contexa.autonomous",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties({
    ContexaProperties.class,
    SecurityPlaneProperties.class,
    SecurityEventProperties.class,
    SecurityZeroTrustProperties.class,
    SecuritySessionProperties.class,
    SecurityColdPathProperties.class,
    SecurityKafkaProperties.class,
    SecurityRedisProperties.class,
    SecurityRouterProperties.class,
    SecurityPipelineProperties.class
})
@Import({
    SecurityPlaneConfiguration.class
})
public class CoreAutonomousAutoConfiguration {

    public CoreAutonomousAutoConfiguration() {
        // @Bean 방식으로 Autonomous 컴포넌트 등록
    }

    // ========== Level 1: 독립적 서비스 (5개) ==========

    /**
     * 1-1. TieredEventProcessor - 계층적 이벤트 처리 프로세서
     */
    @Bean
    @ConditionalOnMissingBean
    public TieredEventProcessor tieredEventProcessor() {
        return new TieredEventProcessor();
    }

    /**
     * 1-2. SecurityEventEnricher - 보안 이벤트 강화 유틸리티
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityEventEnricher securityEventEnricher() {
        return new SecurityEventEnricher();
    }

    /**
     * 1-3. DynamicStrategySelector - 동적 전략 선택기
     */
    @Bean
    @ConditionalOnMissingBean
    public DynamicStrategySelector dynamicStrategySelector(
            ThreatCorrelator threatCorrelator) {
        return new DynamicStrategySelector(threatCorrelator);
    }

    /**
     * 1-4. MaliciousPatternDetector - 악성 패턴 탐지기
     */
    @Bean
    @ConditionalOnMissingBean
    public MaliciousPatternDetector maliciousPatternDetector(
            @Qualifier("stringRedisTemplate") RedisTemplate<String, String> stringRedisTemplate) {
        return new MaliciousPatternDetector(stringRedisTemplate);
    }

    /**
     * 1-5. LayerFeedbackService - 계층별 피드백 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public LayerFeedbackService layerFeedbackService(
            @Autowired(required = false) UnifiedVectorService unifiedVectorService,
            RedisTemplate<String, Object> redisTemplate,
            FeedbackIntegrationProperties feedbackIntegrationProperties) {
        return new LayerFeedbackService(unifiedVectorService, redisTemplate, feedbackIntegrationProperties);
    }

    // ========== Level 2: Level 1 의존 (4개) ==========

    /**
     * 2-1. Layer1PromptTemplate - Layer 1 프롬프트 템플릿
     */
    @Bean
    @ConditionalOnMissingBean
    public Layer1PromptTemplate layer1PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher) {
        return new Layer1PromptTemplate(securityEventEnricher);
    }

    /**
     * 2-2. Layer2PromptTemplate - Layer 2 프롬프트 템플릿
     */
    @Bean
    @ConditionalOnMissingBean
    public Layer2PromptTemplate layer2PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher) {
        return new Layer2PromptTemplate(securityEventEnricher);
    }

    /**
     * 2-3. Layer3PromptTemplate - Layer 3 프롬프트 템플릿
     */
    @Bean
    @ConditionalOnMissingBean
    public Layer3PromptTemplate layer3PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher) {
        return new Layer3PromptTemplate(securityEventEnricher);
    }

    // ========== Level 3: 독립적/선택적 의존 (6개) ==========

    /**
     * 3-1. VectorStoreCacheLayer - Vector Store 캐시 레이어
     */
    @Bean
    @ConditionalOnMissingBean
    public VectorStoreCacheLayer vectorStoreCacheLayer() {
        return new VectorStoreCacheLayer();
    }

    /**
     * 3-2. ValidationHandler - 보안 이벤트 유효성 검증 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.handler.ValidationHandler validationHandler() {
        return new io.contexa.contexacore.autonomous.orchestrator.handler.ValidationHandler();
    }

    // AI Native: VectorSimilarityHandler 제거
    // - 유사도 기반 규칙으로 신뢰도/위험도 계산하는 것은 AI Native 명제 위반
    // - HCAD 유사도는 HCADFilter에서 계산하여 SecurityEvent에 전달
    // - 신뢰도/위험도는 LLM이 직접 분석하여 결정

    /**
     * 3-3. AuditingHandler - 감사 로깅 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.handler.AuditingHandler auditingHandler() {
        return new io.contexa.contexacore.autonomous.orchestrator.handler.AuditingHandler();
    }

    /**
     * 3-5. MetricsHandler - 메트릭스 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.handler.MetricsHandler metricsHandler(
            RedisTemplate<String, Object> redisTemplate) {
        return new io.contexa.contexacore.autonomous.orchestrator.handler.MetricsHandler(redisTemplate);
    }

    /**
     * 3-6. ThreatScoreHandler - Threat Score 업데이트 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.handler.ThreatScoreHandler threatScoreHandler() {
        return new io.contexa.contexacore.autonomous.orchestrator.handler.ThreatScoreHandler();
    }

    /**
     * 3-7. ThreatScoreOrchestrator - 중앙집중식 Threat Score 관리자
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator threatScoreOrchestrator(
            io.contexa.contexacore.infra.redis.RedisAtomicOperations redisAtomicOperations,
            RedisTemplate<String, Object> redisTemplate,
            com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
        return new io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator(
            redisAtomicOperations, redisTemplate, objectMapper
        );
    }

    /**
     * 3-9. SoarContextProviderImpl - SOAR Context Provider 구현체
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.service.impl.SoarContextProviderImpl soarContextProviderImpl() {
        return new io.contexa.contexacore.autonomous.service.impl.SoarContextProviderImpl();
    }

    // ========== Level 4: Level 3 의존 (3개) ==========

    /**
     * 4-1. SecurityMonitoringService - 보안 모니터링 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityMonitoringService securityMonitoringService(
            @Autowired(required = false) io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector kafkaCollector,
            @Autowired(required = false) io.contexa.contexacore.autonomous.event.listener.RedisSecurityEventCollector redisCollector,
            SecurityIncidentRepository securityIncidentRepository,
            ThreatIndicatorRepository indicatorRepository,
            @Autowired(required = false) java.util.List<io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy> evaluationStrategies,
            @Autowired(required = false) io.contexa.contexacore.autonomous.processor.EventNormalizer eventNormalizer,
            @Autowired(required = false) io.contexa.contexacore.autonomous.processor.EventDeduplicator eventDeduplicator,
            @Autowired(required = false) SecurityEventEnricher eventEnricher,
            @Value("${security.plane.monitor.queue-size:10000}") int queueSize,
            @Value("${security.plane.monitor.worker-threads:5}") int workerThreads,
            @Value("${security.plane.monitor.correlation-window-minutes:10}") int correlationWindowMinutes,
            @Value("${security.plane.monitor.threat-threshold:0.7}") double threatThreshold,
            @Value("${security.plane.monitor.auto-incident-creation:true}") boolean autoIncidentCreation,
            @Value("${security.plane.monitor.dedup-window-minutes:5}") int dedupWindowMinutes) {
        return new SecurityMonitoringService(
            kafkaCollector, redisCollector, securityIncidentRepository, indicatorRepository,
            evaluationStrategies, eventNormalizer, eventDeduplicator, eventEnricher,
            queueSize, workerThreads, correlationWindowMinutes, threatThreshold,
            autoIncidentCreation, dedupWindowMinutes
        );
    }

    /**
     * 4-3. AnomalyDetectionService - 통계 기반 이상 탐지 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.service.AnomalyDetectionService anomalyDetectionService(
            RedisTemplate<String, Object> redisTemplate,
            io.contexa.contexacore.hcad.service.HCADVectorIntegrationService hcadVectorIntegrationService) {
        return new io.contexa.contexacore.autonomous.service.AnomalyDetectionService(
            redisTemplate, hcadVectorIntegrationService
        );
    }

    // ========== Level 5: Level 4 의존 (5개) ==========

    /**
     * 5-1. Layer1FastFilterStrategy - Layer 1 초고속 필터링 전략
     *
     * AI Native 전환:
     * - AdaptiveThresholdManager, HCADFeedbackOrchestrator 제거
     * - LLM riskScore 기반 판단으로 전환
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.tiered.strategy.Layer1FastFilterStrategy layer1FastFilterStrategy(
            @Autowired(required = false) io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator llmOrchestrator,
            @Autowired(required = false) io.contexa.contexacore.std.rag.service.UnifiedVectorService unifiedVectorService,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher,
            Layer1PromptTemplate layer1PromptTemplate,
            FeedbackIntegrationProperties feedbackProperties,
            @Autowired(required = false) BaselineLearningService baselineLearningService) {
        return new Layer1FastFilterStrategy(
            llmOrchestrator, unifiedVectorService, redisTemplate,
            securityEventEnricher, layer1PromptTemplate, feedbackProperties,
            baselineLearningService
        );
    }

    /**
     * 5-2. Layer2ContextualStrategy - Layer 2 컨텍스트 기반 분석 전략
     *
     * AI Native 전환:
     * - AdaptiveThresholdManager, HCADFeedbackOrchestrator 제거
     * - LLM riskScore 기반 판단으로 전환
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.tiered.strategy.Layer2ContextualStrategy layer2ContextualStrategy(
            @Autowired(required = false) io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator llmOrchestrator,
            @Autowired(required = false) io.contexa.contexacore.std.rag.service.UnifiedVectorService unifiedVectorService,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher,
            @Autowired(required = false) Layer2PromptTemplate layer2PromptTemplate,
            @Autowired(required = false) io.contexa.contexacore.hcad.service.HCADVectorIntegrationService hcadVectorService,
            @Autowired(required = false) io.contexa.contexacore.std.labs.behavior.BehaviorVectorService behaviorVectorService,
            @Autowired(required = false) io.contexa.contexacore.hcad.service.BaselineLearningService baselineLearningService) {
        return new Layer2ContextualStrategy(
            llmOrchestrator, unifiedVectorService, redisTemplate, securityEventEnricher,
            layer2PromptTemplate,behaviorVectorService, baselineLearningService
        );
    }
    /**
     * 5-3. Layer3ExpertStrategy - Layer 3 전문가 시스템 전략
     *
     * AI Native 전환:
     * - AdaptiveThresholdManager, HCADFeedbackOrchestrator 제거
     * - LLM riskScore 기반 판단으로 전환
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.tiered.strategy.Layer3ExpertStrategy layer3ExpertStrategy(
            @Autowired(required = false) io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator llmOrchestrator,
            @Autowired(required = false) io.contexa.contexacore.std.labs.AILabFactory labFactory,
            @Autowired(required = false) io.contexa.contexacore.soar.approval.ApprovalService approvalService,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher,
            @Autowired(required = false) Layer3PromptTemplate layer3PromptTemplate,
            @Autowired(required = false) io.contexa.contexacore.hcad.service.HCADVectorIntegrationService hcadVectorService,
            @Autowired(required = false) io.contexa.contexacore.std.labs.behavior.BehaviorVectorService behaviorVectorService,
            io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties feedbackProperties,
            @Autowired(required = false) io.contexa.contexacore.std.rag.service.UnifiedVectorService unifiedVectorService,
            @Autowired(required = false) io.contexa.contexacore.hcad.service.BaselineLearningService baselineLearningService) {
        return new Layer3ExpertStrategy(
            llmOrchestrator, approvalService, redisTemplate, securityEventEnricher,
            layer3PromptTemplate, unifiedVectorService, behaviorVectorService, feedbackProperties,
            baselineLearningService
        );
    }
    /**
     * 5-4. RoutingDecisionHandler - 라우팅 결정 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.handler.RoutingDecisionHandler routingDecisionHandler() {
        return new io.contexa.contexacore.autonomous.orchestrator.handler.RoutingDecisionHandler();
    }

    /**
     * 5-5. SecurityEventProcessingOrchestrator - 보안 이벤트 처리 오케스트레이터
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.SecurityEventProcessingOrchestrator securityEventProcessingOrchestrator(
            java.util.List<io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler> handlers) {
        return new io.contexa.contexacore.autonomous.orchestrator.SecurityEventProcessingOrchestrator(handlers);
    }

    // ========== Level 6: Level 5 의존 (1개) ==========

    /**
     * 6-1. SecurityPlaneAgent - Security Plane 에이전트 메인 클래스
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.SecurityPlaneAgent securityPlaneAgent(
            io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService securityMonitor,
            io.contexa.contexacore.repository.SecurityIncidentRepository incidentRepository,
            RedisTemplate<String, Object> redisTemplate,
            org.springframework.context.ApplicationEventPublisher eventPublisher,
            io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger auditLogger,
            io.contexa.contexacore.autonomous.orchestrator.SecurityEventProcessingOrchestrator processingOrchestrator) {
        return new io.contexa.contexacore.autonomous.SecurityPlaneAgent(
            securityMonitor, incidentRepository, redisTemplate, eventPublisher, auditLogger, processingOrchestrator
        );
    }

}

