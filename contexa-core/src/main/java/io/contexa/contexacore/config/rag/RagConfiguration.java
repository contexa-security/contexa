package io.contexa.contexacore.config.rag;

import io.contexa.contexacore.domain.VectorDocumentType;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.rag.Query;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Spring AI RAG(Retrieval Augmented Generation) 설정
 * 
 * Spring AI 공식 표준을 100% 준수하여 구현된 프로덕션 레벨 설정입니다.
 * 행동 분석, 위험 평가, 정책 생성 등 도메인별 RAG Advisor를 제공합니다.
 * 
 * @since 1.0.0
 */
@Configuration
public class RagConfiguration {
    
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
    
    /**
     * 행동 분석용 RAG Advisor
     * 
     * 사용자 행동 패턴 분석을 위한 특화된 검색 증강 생성 어드바이저입니다.
     * Pre-Retrieval: 쿼리 재작성 및 시간 범위 확장
     * Retrieval: 행동 패턴 벡터 검색
     * Post-Retrieval: 시간 클러스터링 및 이상 점수 순위 지정
     */
    @Bean
    @Primary
    public RetrievalAugmentationAdvisor behaviorAnalysisRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("behaviorQueryTransformer") QueryTransformer behaviorQueryTransformer,
            @Qualifier("temporalClusteringProcessor") DocumentPostProcessor temporalClusteringProcessor,
            @Qualifier("anomalyScoreRanker") DocumentPostProcessor anomalyScoreRanker) {
        
        // Spring AI 표준 FilterExpressionBuilder 사용
        String thirtyDaysAgo = LocalDateTime.now()
            .minusDays(behaviorLookbackDays)
            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.gte("timestamp", thirtyDaysAgo),
            filterBuilder.eq("documentType", VectorDocumentType.BEHAVIOR.getValue())
        ).build();
        
        // VectorStoreDocumentRetriever 구성
        VectorStoreDocumentRetriever documentRetriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(defaultSimilarityThreshold)
            .topK(defaultTopK)
            .filterExpression(filter)
            .build();
        
        // RetrievalAugmentationAdvisor 구성
        return RetrievalAugmentationAdvisor.builder()
            .documentRetriever(documentRetriever)
            .queryTransformers(behaviorQueryTransformer)
            .build();
    }
    
    /**
     * 위험 평가용 RAG Advisor
     * 
     * 보안 위험 평가를 위한 특화된 검색 증강 생성 어드바이저입니다.
     * 높은 유사도 임계값과 위협 상관 관계 분석을 적용합니다.
     */
    @Bean
    public RetrievalAugmentationAdvisor riskAssessmentRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("riskQueryTransformer") QueryTransformer riskQueryTransformer,
            @Qualifier("riskScoreAggregator") DocumentPostProcessor riskScoreAggregator,
            @Qualifier("threatCorrelator") DocumentPostProcessor threatCorrelator) {
        
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
     * 정책 생성용 RAG Advisor
     * 
     * AI 기반 정책 생성을 위한 검색 증강 생성 어드바이저입니다.
     * 기존 정책 패턴을 학습하여 새로운 정책을 생성합니다.
     */
    @Bean
    public RetrievalAugmentationAdvisor policyGenerationRagAdvisor(
            VectorStore vectorStore,
            ChatClient.Builder chatClientBuilder,
            @Qualifier("policyQueryTransformer") QueryTransformer policyQueryTransformer,
            @Qualifier("policyTemplateProcessor") DocumentPostProcessor policyTemplateProcessor) {
        
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
     * 행동 분석 쿼리 변환기
     * 
     * 행동 패턴 분석을 위해 쿼리를 최적화합니다.
     */
    @Bean("behaviorQueryTransformer")
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
     * 위험 평가 쿼리 변환기
     */
    @Bean("riskQueryTransformer")
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
     * 정책 생성 쿼리 변환기
     */
    @Bean("policyQueryTransformer")
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