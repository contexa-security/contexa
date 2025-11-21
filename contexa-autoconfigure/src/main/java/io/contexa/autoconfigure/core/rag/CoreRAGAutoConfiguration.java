package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.config.VectorStoreObservationConfig;
import io.contexa.contexacore.config.rag.RagConfiguration;
import io.contexa.contexacore.infra.redis.DistributedAIStrategyCoordinator;
import io.contexa.contexacore.infra.redis.RedisDistributedLockService;
import io.contexa.contexacore.infra.redis.RedisEventPublisher;
import io.contexa.contexacore.infra.session.AIStrategySessionRepository;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.labs.risk.RiskAssessmentVectorService;
import io.contexa.contexacore.std.llm.dynamic.AIModelManager;
import io.contexa.contexacore.std.llm.dynamic.AIModelUsage;
import io.contexa.contexacore.std.llm.model.DynamicModelRegistry;
import io.contexa.contexacore.std.llm.service.ModelDiscoveryService;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexacore.std.operations.DistributedSessionManager;
import io.contexa.contexacore.std.operations.DistributedStrategyExecutor;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.rag.etl.BehaviorETLPipeline;
import io.contexa.contexacore.std.rag.properties.PgVectorStoreProperties;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Core RAG AutoConfiguration
 *
 * Contexa 프레임워크의 RAG 관련 자동 구성을 제공합니다.
 * Import 방식으로 기존 Configuration 클래스들을 재사용합니다.
 *
 * 포함된 Configuration:
 * - RagConfiguration - Spring AI RAG Advisor 시스템
 * - VectorStoreObservationConfig - VectorStore 관찰성 설정
 *
 * 활성화 조건:
 * contexa:
 *   rag:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.rag",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
@Import({
    RagConfiguration.class,
    VectorStoreObservationConfig.class
})
public class CoreRAGAutoConfiguration {

    public CoreRAGAutoConfiguration() {
        // Import만 수행, STD Service Bean들은 아래 메서드에서 등록
    }

    /**
     * 1단계: StandardVectorStoreService
     * Spring AI 표준 VectorStore 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public StandardVectorStoreService standardVectorStoreService(
            PgVectorStoreProperties properties,
            VectorStore vectorStore,
            EmbeddingModel embeddingModel,
            JdbcTemplate jdbcTemplate) {
        return new StandardVectorStoreService(
            properties, vectorStore, embeddingModel, jdbcTemplate
        );
    }

    /**
     * 1단계: ModelDiscoveryService
     * LLM 모델 발견 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public ModelDiscoveryService modelDiscoveryService(
            ApplicationContext applicationContext,
            DynamicModelRegistry modelRegistry) {
        return new ModelDiscoveryService(
            applicationContext, modelRegistry
        );
    }

    /**
     * 1단계: AIModelManager
     * 동적 AI 모델 관리 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public AIModelManager aiModelManager() {
        return new AIModelManager();
    }

    /**
     * 1단계: DistributedSessionManager
     * 분산 세션 관리 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public DistributedSessionManager distributedSessionManager(
            RedisEventPublisher eventPublisher,
            AuditLogger auditLogger) {
        return new DistributedSessionManager(
            eventPublisher, auditLogger
        );
    }

    /**
     * 2단계: BehaviorVectorService
     * 행동 분석 전용 벡터 저장소 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public BehaviorVectorService behaviorVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics,
            BehaviorETLPipeline behaviorETLPipeline,
            AuditLogRepository auditLogRepository) {
        return new BehaviorVectorService(
            standardVectorStoreService, vectorStoreMetrics, behaviorETLPipeline, auditLogRepository
        );
    }

    /**
     * 2단계: RiskAssessmentVectorService
     * Zero Trust 위험 평가 전용 벡터 저장소 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public RiskAssessmentVectorService riskAssessmentVectorService(
            StandardVectorStoreService standardVectorStoreService,
            @Autowired(required = false) VectorStoreMetrics vectorStoreMetrics) {
        return new RiskAssessmentVectorService(
            standardVectorStoreService, vectorStoreMetrics
        );
    }

    /**
     * 2단계: AIModelUsage
     * AI 모델 사용 예시 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public AIModelUsage aiModelUsage(
            AIModelManager aiModelManager) {
        return new AIModelUsage(aiModelManager);
    }

    /**
     * 2단계: DistributedStrategyExecutor
     * 분산 전략 실행 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public DistributedStrategyExecutor distributedStrategyExecutor(
            PipelineOrchestrator orchestrator,
            @Qualifier("aiStrategySessionRepository") AIStrategySessionRepository sessionRepository,
            DistributedAIStrategyCoordinator strategyCoordinator,
            RedisEventPublisher eventPublisher,
            AIStrategyRegistry strategyRegistry) {
        return new DistributedStrategyExecutor(
            orchestrator, sessionRepository, strategyCoordinator, eventPublisher, strategyRegistry
        );
    }

    /**
     * 3단계: UnifiedVectorService
     * 통합 Vector Store 서비스 (모든 벡터 저장 및 검색의 단일 진입점)
     */
    @Bean
    @ConditionalOnMissingBean
    public UnifiedVectorService unifiedVectorService(
            VectorStoreCacheLayer cacheLayer,
            StandardVectorStoreService standardService,
            BehaviorVectorService behaviorService,
            RiskAssessmentVectorService riskService) {
        return new UnifiedVectorService(
            cacheLayer, standardService, behaviorService, riskService
        );
    }

    /**
     * 3단계: AINativeProcessor
     * AI Native IAM Operations Master Brain
     */
    @Bean
    @ConditionalOnMissingBean
    public AINativeProcessor aiNativeProcessor(
            DistributedSessionManager sessionManager,
            RedisDistributedLockService distributedLockService,
            DistributedStrategyExecutor distributedStrategyExecutor) {
        return new AINativeProcessor(
            sessionManager, distributedLockService, distributedStrategyExecutor
        );
    }
}
