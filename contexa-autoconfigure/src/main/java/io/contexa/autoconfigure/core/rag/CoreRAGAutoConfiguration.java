package io.contexa.autoconfigure.core.rag;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacommon.metrics.VectorStoreMetrics;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.observation.SecurityVectorStoreObservationConvention;
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
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.ai.vectorstore.observation.VectorStoreObservationConvention;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Core RAG AutoConfiguration
 *
 * Contexa 프레임워크의 RAG 관련 자동 구성을 제공합니다.
 *
 * 포함된 Bean (17개):
 * Observability (1개):
 * - securityVectorStoreObservationConvention - VectorStore 관찰성
 *
 * RAG Advisors (3개):
 * - behaviorAnalysisRagAdvisor - 행동 분석용 RAG Advisor (@Primary)
 * - riskAssessmentRagAdvisor - 위험 평가용 RAG Advisor
 * - policyGenerationRagAdvisor - 정책 생성용 RAG Advisor
 *
 * Query Transformers (3개):
 * - behaviorQueryTransformer - 행동 분석 쿼리 변환기
 * - riskQueryTransformer - 위험 평가 쿼리 변환기
 * - policyQueryTransformer - 정책 생성 쿼리 변환기
 *
 * STD Service Beans (10개):
 * - StandardVectorStoreService, ModelDiscoveryService, AIModelManager
 * - DistributedSessionManager, BehaviorVectorService, RiskAssessmentVectorService
 * - AIModelUsage, DistributedStrategyExecutor, UnifiedVectorService, AINativeProcessor
 *
 * 활성화 조건:
 * contexa:
 *   rag:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@Slf4j
@AutoConfiguration
@AutoConfigureAfter(io.contexa.autoconfigure.core.advisor.CoreAdvisorAutoConfiguration.class)
@ConditionalOnProperty(
    prefix = "contexa.rag",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContexaProperties.class)
public class CoreRAGAutoConfiguration {

    @Value("${spring.ai.rag.similarity-threshold:0.75}")
    private double defaultSimilarityThreshold;

    @Value("${spring.ai.rag.top-k:100}")
    private int defaultTopK;

    @Value("${spring.ai.rag.behavior.lookback-days:30}")
    private int behaviorLookbackDays;

    @Value("${spring.ai.rag.risk.similarity-threshold:0.8}")
    private double riskSimilarityThreshold;

    @Value("${spring.ai.rag.risk.top-k:50}")
    private int riskTopK;

    public CoreRAGAutoConfiguration() {
        log.info("=== CoreRAGAutoConfiguration initialized ===");
        log.info("VectorStore Observability: ENABLED");
    }

    /**
     * VectorStore Observability: SecurityVectorStoreObservationConvention
     *
     * Spring AI VectorStore의 모든 작업에 대해 보안 관련 관찰성을 제공합니다.
     * PgVectorStore가 자동으로 이 Convention을 사용합니다.
     */
    @Bean
    @ConditionalOnMissingBean
    public VectorStoreObservationConvention securityVectorStoreObservationConvention() {
        log.info("=== Registering SecurityVectorStoreObservationConvention ===");
        log.info("PgVectorStore will automatically use this convention for all operations");
        return new SecurityVectorStoreObservationConvention();
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

    // ===== Spring AI RAG Advisors (6개) =====

    /**
     * RAG 1: 행동 분석용 RAG Advisor
     *
     * 사용자 행동 패턴 분석을 위한 특화된 검색 증강 생성 어드바이저입니다.
     */
    @Bean
    @Primary
    @ConditionalOnMissingBean(name = "behaviorAnalysisRagAdvisor")
    public RetrievalAugmentationAdvisor behaviorAnalysisRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("behaviorQueryTransformer") QueryTransformer behaviorQueryTransformer) {

        String thirtyDaysAgo = LocalDateTime.now()
            .minusDays(behaviorLookbackDays)
            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.gte("timestamp", thirtyDaysAgo),
            filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue())
        ).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(defaultSimilarityThreshold)
            .topK(defaultTopK)
            .filterExpression(filter)
            .build();

        return RetrievalAugmentationAdvisor.builder()
            .documentRetriever(documentRetriever)
            .queryTransformers(behaviorQueryTransformer)
            .build();
    }

    /**
     * RAG 2: 위험 평가용 RAG Advisor
     *
     * 보안 위험 평가를 위한 특화된 검색 증강 생성 어드바이저입니다.
     */
    @Bean
    @ConditionalOnMissingBean(name = "riskAssessmentRagAdvisor")
    public RetrievalAugmentationAdvisor riskAssessmentRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("riskQueryTransformer") QueryTransformer riskQueryTransformer) {

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.eq("documentType", VectorDocumentType.RISK_ASSESSMENT.getValue()),
            filterBuilder.gte("riskScore", 0.5)
        ).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(riskSimilarityThreshold)
            .topK(riskTopK)
            .filterExpression(filter)
            .build();

        return RetrievalAugmentationAdvisor.builder()
            .documentRetriever(documentRetriever)
            .queryTransformers(riskQueryTransformer)
            .build();
    }

    /**
     * RAG 3: 정책 생성용 RAG Advisor
     *
     * AI 기반 정책 생성을 위한 검색 증강 생성 어드바이저입니다.
     */
    @Bean
    @ConditionalOnMissingBean(name = "policyGenerationRagAdvisor")
    public RetrievalAugmentationAdvisor policyGenerationRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("policyQueryTransformer") QueryTransformer policyQueryTransformer) {

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.eq("documentType", VectorDocumentType.POLICY_EVOLUTION.getValue()).build();

        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(0.7)
            .topK(20)
            .filterExpression(filter)
            .build();

        return RetrievalAugmentationAdvisor.builder()
            .documentRetriever(documentRetriever)
            .queryTransformers(policyQueryTransformer)
            .build();
    }

    /**
     * Query Transformer 1: 행동 분석 쿼리 변환기
     */
    @Bean("behaviorQueryTransformer")
    @ConditionalOnMissingBean(name = "behaviorQueryTransformer")
    public QueryTransformer behaviorQueryTransformer(ChatClient.Builder chatClientBuilder) {
        return new QueryTransformer() {
            private final ChatClient chatClient = chatClientBuilder.build();

            @Override
            public Query transform(Query originalQuery) {
                if (originalQuery == null || originalQuery.text() == null) {
                    return originalQuery;
                }

                String prompt = """
                    사용자 행동 패턴 분석을 위해 다음 쿼리를 최적화하세요:

                    원본 쿼리: %s

                    최적화 지침:
                    1. 시간적 컨텍스트를 포함시키세요 (최근 30일)
                    2. 유사 행동 패턴을 검색할 수 있는 키워드를 추가하세요
                    3. 이상 징후 관련 용어를 강화하세요
                    4. 사용자 역할과 권한 컨텍스트를 고려하세요

                    최적화된 쿼리만 반환하세요.
                    """.formatted(originalQuery.text());

                String transformedText = chatClient.prompt()
                    .user(prompt)
                    .call()
                    .content();

                return new Query(transformedText);
            }
        };
    }

    /**
     * Query Transformer 2: 위험 평가 쿼리 변환기
     */
    @Bean("riskQueryTransformer")
    @ConditionalOnMissingBean(name = "riskQueryTransformer")
    public QueryTransformer riskQueryTransformer(ChatClient.Builder chatClientBuilder) {
        return new QueryTransformer() {
            private final ChatClient chatClient = chatClientBuilder.build();

            @Override
            public Query transform(Query originalQuery) {
                if (originalQuery == null || originalQuery.text() == null) {
                    return originalQuery;
                }

                String prompt = """
                    보안 위험 평가를 위해 다음 쿼리를 최적화하세요:

                    원본 쿼리: %s

                    최적화 지침:
                    1. 위협 지표(IOC)를 포함시키세요
                    2. 과거 인시던트 패턴을 검색할 수 있도록 확장하세요
                    3. 리스크 수준별 분류 키워드를 추가하세요
                    4. MITRE ATT&CK 프레임워크 관련 용어를 포함하세요

                    최적화된 쿼리만 반환하세요.
                    """.formatted(originalQuery.text());

                String transformedText = chatClient.prompt()
                    .user(prompt)
                    .call()
                    .content();

                return new Query(transformedText);
            }
        };
    }

    /**
     * Query Transformer 3: 정책 생성 쿼리 변환기
     */
    @Bean("policyQueryTransformer")
    @ConditionalOnMissingBean(name = "policyQueryTransformer")
    public QueryTransformer policyQueryTransformer(ChatClient.Builder chatClientBuilder) {
        return new QueryTransformer() {
            private final ChatClient chatClient = chatClientBuilder.build();

            @Override
            public Query transform(Query originalQuery) {
                if (originalQuery == null || originalQuery.text() == null) {
                    return originalQuery;
                }

                String prompt = """
                    정책 생성을 위해 다음 쿼리를 최적화하세요:

                    원본 쿼리: %s

                    최적화 지침:
                    1. 유사한 정책 템플릿을 찾을 수 있도록 확장하세요
                    2. 역할 기반 접근 제어(RBAC) 관련 용어를 포함하세요
                    3. 컴플라이언스 요구사항을 고려하세요
                    4. 비즈니스 규칙과 조건을 포함하세요

                    최적화된 쿼리만 반환하세요.
                    """.formatted(originalQuery.text());

                String transformedText = chatClient.prompt()
                    .user(prompt)
                    .call()
                    .content();

                return new Query(transformedText);
            }
        };
    }
}
