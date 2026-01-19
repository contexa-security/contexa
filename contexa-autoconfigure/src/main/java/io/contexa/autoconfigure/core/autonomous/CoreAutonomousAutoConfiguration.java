package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration;
import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.autonomous.config.SecurityPlaneConfiguration;
import io.contexa.contexacore.autonomous.config.TieredStrategyProperties;
import io.contexa.contexacore.autonomous.service.AdminOverrideRepository;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.strategy.DynamicStrategySelector;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.detection.MaliciousPatternDetector;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer1ContextualStrategy;
import io.contexa.contexacore.autonomous.tiered.strategy.Layer2ExpertStrategy;
import io.contexa.contexacore.autonomous.tiered.service.SecurityDecisionPostProcessor;
import io.contexa.contexacore.autonomous.tiered.template.SecurityPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
import io.contexa.contexacore.properties.*;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.std.rag.processors.ThreatCorrelator;
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

    // AI Native v4.0.0: TieredEventProcessor 제거
    // - LLM 분석 전 사전 필터링/분류는 AI Native 원칙 위반
    // - 모든 이벤트를 동일 토픽으로 발행하고 LLM이 분류 결정

    /**
     * 1-1. SecurityEventEnricher - 보안 이벤트 강화 유틸리티
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
     * 1-6. TieredStrategyProperties - Tiered 전략 설정 (Phase 4 추가)
     */
    @Bean
    @ConditionalOnMissingBean
    public TieredStrategyProperties tieredStrategyProperties() {
        return new TieredStrategyProperties();
    }

    /**
     * 1-7. AdminOverrideRepository - 관리자 개입 Redis 저장소 (AI Native v3.4.0)
     *
     * AI Native 원칙:
     * - BLOCK 판정된 요청에 대한 관리자 검토 이력을 영구 저장
     * - 모든 관리자 개입은 감사 로그로 30일간 보존
     */
    @Bean
    @ConditionalOnMissingBean
    public AdminOverrideRepository adminOverrideRepository(
            RedisTemplate<String, Object> redisTemplate) {
        return new AdminOverrideRepository(redisTemplate);
    }

    /**
     * 2-2. SecurityPromptTemplate - 통합 보안 프롬프트 템플릿 (AI Native v6.6)
     *
     * L1 = L2 원칙: Layer1과 Layer2 모두 동일한 프롬프트 템플릿 사용
     * 차이점은 LLM 모델만 다름 (layer1.model vs layer2.model)
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityPromptTemplate securityPromptTemplate(
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties,
            BaselineLearningService baselineLearningService) {
        return new SecurityPromptTemplate(securityEventEnricher, tieredStrategyProperties,baselineLearningService);
    }

    /**
     * 2-4. AdminOverrideService - 관리자 개입 서비스 (AI Native v3.4.0)
     *
     * AI Native 원칙:
     * - LLM 판정은 최종 결정이 아님 (관리자 개입 가능)
     * - 그러나 관리자 개입은 명시적 승인 + 기준선 업데이트 허용이 별도로 필요
     * - 모든 개입은 감사 로그로 기록됨
     *
     * 기준선 오염 방지 메커니즘:
     * - 관리자 승인만으로는 기준선 업데이트되지 않음
     * - baselineUpdateAllowed=true를 명시적으로 설정해야 함
     *
     * AI Native v3.5.0 추가:
     * - Redis analysis 키 업데이트 (MFA 성공 케이스와 동일 패턴)
     * - ALLOW 승인 시 tryAcquireAnalysisLock() 차단 방지
     */
    @Bean
    @ConditionalOnMissingBean
    public AdminOverrideService adminOverrideService(
            AdminOverrideRepository adminOverrideRepository,
            @Autowired(required = false) BaselineLearningService baselineLearningService,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate) {
        return new AdminOverrideService(adminOverrideRepository, baselineLearningService, redisTemplate);
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

    // AI Native: ValidationHandler 제거
    // - 중복 이벤트 필터링: EventDeduplicator에서 더 우수하게 처리 (Caffeine 캐시 + SHA-256 해시)
    // - 시간 기반 필터링 (24시간): AI Native 원칙 위반 (규칙 기반)
    // - 필수 필드 검증: SecurityEvent 생성 시점에서 처리해야 함

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

    // AI Native: ThreatScoreHandler 제거 (v3.1.0)
    // - 핸들러 체인에서 직접 ThreatScoreOrchestrator.saveThreatScore() 호출로 대체
    // - 불필요한 중간 레이어 제거

    /**
     * 3-7. ThreatScoreOrchestrator - AI Native Threat Score 관리자
     *
     * AI Native 리팩토링 (v3.1.0):
     * - RedisAtomicOperations, ObjectMapper 의존성 제거
     * - 단순 RedisTemplate만 사용
     */
    @Bean
    @ConditionalOnMissingBean
    public io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator threatScoreOrchestrator(
            RedisTemplate<String, Object> redisTemplate) {
        return new io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator(redisTemplate);
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
     *
     * AI Native v5.0.0: 비동기 구조 최적화
     * - BlockingQueue 제거 (Kafka Batch Listener로 대체)
     * - queueSize, dedupWindowMinutes 파라미터 제거
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
            @Value("${security.plane.monitor.worker-threads:5}") int workerThreads,
            @Value("${security.plane.monitor.correlation-window-minutes:10}") int correlationWindowMinutes,
            @Value("${security.plane.monitor.threat-threshold:0.7}") double threatThreshold,
            @Value("${security.plane.monitor.auto-incident-creation:true}") boolean autoIncidentCreation) {
        return new SecurityMonitoringService(
            kafkaCollector, redisCollector, securityIncidentRepository, indicatorRepository,
            evaluationStrategies, eventNormalizer, eventDeduplicator, eventEnricher,
            workerThreads, correlationWindowMinutes, threatThreshold, autoIncidentCreation
        );
    }

    /**
     * 5-2. Layer1ContextualStrategy - Layer 1 컨텍스트 기반 분석 전략
     *
     * AI Native v6.6: L1 = L2 원칙 적용
     * - 통합 SecurityPromptTemplate 사용
     * - 차이점은 LLM 모델만 다름
     */
    @Bean
    @ConditionalOnMissingBean
    public Layer1ContextualStrategy contextualStrategy(
            @Autowired(required = false) io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator llmOrchestrator,
            @Autowired(required = false) io.contexa.contexacore.std.rag.service.UnifiedVectorService unifiedVectorService,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher,
            @Autowired(required = false) SecurityPromptTemplate securityPromptTemplate,
            @Autowired(required = false) io.contexa.contexacore.std.labs.behavior.BehaviorVectorService behaviorVectorService,
            @Autowired(required = false) io.contexa.contexacore.hcad.service.BaselineLearningService baselineLearningService,
            @Autowired(required = false) SecurityDecisionPostProcessor securityDecisionPostProcessor,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties) {
        return new Layer1ContextualStrategy(
            llmOrchestrator, unifiedVectorService, redisTemplate, securityEventEnricher,
            securityPromptTemplate, behaviorVectorService, baselineLearningService,
            securityDecisionPostProcessor, tieredStrategyProperties
        );
    }

    /**
     * 5-3. Layer2ExpertStrategy - Layer 2 전문가 시스템 전략
     *
     * AI Native v6.6: L1 = L2 원칙 적용
     * - 통합 SecurityPromptTemplate 사용
     * - 차이점은 LLM 모델만 다름
     */
    @Bean
    @ConditionalOnMissingBean
    public Layer2ExpertStrategy expertStrategy(
            @Autowired(required = false) io.contexa.contexacore.std.llm.core.UnifiedLLMOrchestrator llmOrchestrator,
            @Autowired(required = false) io.contexa.contexacore.soar.approval.ApprovalService approvalService,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher,
            @Autowired(required = false) SecurityPromptTemplate securityPromptTemplate,
            @Autowired(required = false) io.contexa.contexacore.std.rag.service.UnifiedVectorService unifiedVectorService,
            @Autowired(required = false) io.contexa.contexacore.std.labs.behavior.BehaviorVectorService behaviorVectorService,
            @Autowired(required = false) io.contexa.contexacore.hcad.service.BaselineLearningService baselineLearningService,
            @Autowired(required = false) TieredStrategyProperties tieredStrategyProperties) {
        return new Layer2ExpertStrategy(
            llmOrchestrator, approvalService, redisTemplate, securityEventEnricher,
            securityPromptTemplate, unifiedVectorService, behaviorVectorService,
            baselineLearningService, tieredStrategyProperties
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

