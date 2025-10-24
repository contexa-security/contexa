package io.contexa.contexacore.soar.retriever;

import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * SOAR (Security Orchestration, Automation and Response) 컨텍스트 검색기
 *
 * Spring AI RAG 기반 SOAR 전용 컨텍스트 검색
 * - SOAR 전용 RAG Advisor 사용
 * - 보안 지식베이스 통합
 * - 위협 상관관계 분석
 */
@Slf4j
@Component
public class SoarContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry registry;
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;
    
    @Autowired(required = false)
    @Qualifier("riskScoreAggregator")
    private DocumentPostProcessor riskScoreAggregator;
    
    @Autowired(required = false)
    @Qualifier("threatCorrelator")
    private DocumentPostProcessor threatCorrelator;
    
    @Value("${spring.ai.rag.soar.similarity-threshold:0.75}")
    private double soarSimilarityThreshold;
    
    @Value("${spring.ai.rag.soar.top-k:20}")
    private int soarTopK;
    
    @Value("${spring.ai.rag.soar.lookback-hours:24}")
    private int lookbackHours;
    
    private RetrievalAugmentationAdvisor soarAdvisor;

    public SoarContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry) {
        super(vectorStore);
        this.registry = registry;
    }

    @PostConstruct
    public void registerSelf() {
        // SOAR 전용 RAG Advisor 생성 및 등록
        if (chatClientBuilder != null) {
            createSoarAdvisor();
        }
        
        // 레지스트리에 등록
        registry.registerRetriever(SoarContext.class, this);
        log.info("SoarContextRetriever 자동 등록 완료 (Spring AI RAG Advisor 사용)");
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof SoarContext) {
            return retrieveSoarContextWithRAG((AIRequest<SoarContext>) request);
        }
        return super.retrieveContext(request);
    }

    /**
     * SOAR 전용 RAG Advisor 생성
     */
    private void createSoarAdvisor() {
        // SOAR 쿼리 변환기
        QueryTransformer soarQueryTransformer = new SoarQueryTransformer(chatClientBuilder);
        
        // SOAR 필터 구성
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType",
                "incident",  // TODO: VectorDocumentType에 추가 필요
                VectorDocumentType.THREAT.getValue(),
                "security_alert",  // TODO: VectorDocumentType에 추가 필요
                "soar_playbook"),  // TODO: VectorDocumentType에 추가 필요
            filterBuilder.gte("severity", 0.5)
        ).build();
        
        // VectorStoreDocumentRetriever 구성
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(soarSimilarityThreshold)
            .topK(soarTopK)
            .filterExpression(filter)
            .build();
        
        // SOAR RAG Advisor 생성
        soarAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(soarQueryTransformer)
            .build();
        
        // 부모 클래스에 SOAR Advisor 등록
        registerDomainAdvisor(SoarContext.class, soarAdvisor);
    }
    
    /**
     * RAG 기능이 통합된 SOAR 컨텍스트 검색
     */
    private ContextRetrievalResult retrieveSoarContextWithRAG(AIRequest<SoarContext> request) {
        log.info("SOAR 컨텍스트 분석 시작 (Spring AI RAG): {}", request.getContext().getIncidentId());

        try {
            // 부모 클래스의 RAG 기능 활용
            ContextRetrievalResult baseResult = super.retrieveContext(request);
            
            SoarContext context = request.getContext();
            
            // SOAR 전용 컨텍스트 강화
            String enhancedContext = buildComprehensiveContext(
                context, 
                baseResult.getContextInfo(),
                baseResult.getDocuments()
            );

            // SOAR 메타데이터 추가
            Map<String, Object> metadata = new HashMap<>(baseResult.getMetadata());
            metadata.put("retrieverType", "SoarContextRetriever");
            metadata.put("incidentId", context.getIncidentId());
            if (context.getThreatLevel() != null) {
                metadata.put("threatLevel", context.getThreatLevel().toString());
            }
            metadata.put("soarEnhanced", true);

            return new ContextRetrievalResult(
                    enhancedContext,
                    baseResult.getDocuments(),
                    metadata
            );

        } catch (Exception e) {
            log.error("SOAR 컨텍스트 분석 실패", e);
            return new ContextRetrievalResult(
                    getDefaultContext(),
                    List.of(),
                    Map.of("error", e.getMessage())
            );
        }
    }

    /**
     * 보안 지식베이스에서 관련 문서 검색
     */
    private List<Document> searchSecurityKnowledge(SoarContext context) {
        // 검색 쿼리 구성
        String searchQuery = buildSearchQuery(context);

        log.debug("🔎 Vector DB 검색 쿼리: {}", searchQuery);

        // Vector Store에서 유사 문서 검색
        SearchRequest searchRequest = SearchRequest.builder()
                .query(searchQuery)
                .topK(5)  // 상위 5개 문서
                .similarityThreshold(0.7)  // 유사도 임계값
                .build();

        List<Document> documents = vectorStore.similaritySearch(searchRequest);

        log.info("📚 검색된 보안 지식 문서: {}개", documents.size());

        return documents;
    }

    /**
     * 검색 쿼리 구성
     */
    private String buildSearchQuery(SoarContext context) {
        StringBuilder query = new StringBuilder();

        // 위협 유형
        if (context.getThreatType() != null) {
            query.append(context.getThreatType()).append(" ");
        }

        // 설명
        if (context.getDescription() != null) {
            query.append(context.getDescription()).append(" ");
        }

        // 쿼리 의도
        if (context.getQueryIntent() != null) {
            query.append(context.getQueryIntent()).append(" ");
        }

        // 추출된 엔티티
        if (!context.getExtractedEntities().isEmpty()) {
            query.append(context.getExtractedEntities().values()).append(" ");
        }

        return query.toString().trim();
    }

    /**
     * RAG 컨텍스트 추출
     */
    private String extractRagContext(List<Document> documents) {
        if (documents.isEmpty()) {
            return "";
        }

        return documents.stream()
                .map(doc -> {
                    String content = doc.getText();
                    // 문서 메타데이터가 있으면 포함
                    if (doc.getMetadata() != null && !doc.getMetadata().isEmpty()) {
                        String source = doc.getMetadata().getOrDefault("source", "unknown").toString();
                        return String.format("[출처: %s]\n%s", source, content);
                    }
                    return content;
                })
                .collect(Collectors.joining("\n\n"));
    }

    /**
     * 종합 컨텍스트 구성
     */
    private String buildComprehensiveContext(SoarContext context, String baseContext, List<Document> documents) {
        String ragContext = extractRagContext(documents);
        StringBuilder contextBuilder = new StringBuilder();

        contextBuilder.append("## SOAR 분석 컨텍스트\n\n");

        // 1. 인시던트 정보
        contextBuilder.append("### 인시던트 정보\n");
        contextBuilder.append(String.format("- 인시던트 ID: %s\n", context.getIncidentId()));
        contextBuilder.append(String.format("- 위협 유형: %s\n", context.getThreatType()));
        contextBuilder.append(String.format("- 설명: %s\n", context.getDescription()));
        contextBuilder.append(String.format("- 영향받는 자산: %s\n", String.join(", ", context.getAffectedAssets())));
        contextBuilder.append(String.format("- 현재 상태: %s\n", context.getCurrentStatus()));
        contextBuilder.append(String.format("- 탐지 소스: %s\n", context.getDetectedSource()));
        contextBuilder.append(String.format("- 심각도: %s\n", context.getSeverity()));
        contextBuilder.append(String.format("- 권장 조치: %s\n", context.getRecommendedActions()));
        contextBuilder.append(String.format("- 분석 시각: %s\n\n", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)));

        // 2. RAG 기반 보안 지식
        if (ragContext != null && !ragContext.trim().isEmpty()) {
            contextBuilder.append("### 관련 보안 지식 (RAG)\n");
            contextBuilder.append(ragContext);
            contextBuilder.append("\n\n");
        }


        // 5. AI 분석 가이드
        contextBuilder.append("### AI 분석 가이드\n");
        contextBuilder.append("위의 정보를 종합하여 다음을 평가하고 자동화된 조치를 제안해주세요:\n");
        contextBuilder.append("1. 인시던트의 심각도 재평가\n");
        contextBuilder.append("2. 실행할 플레이북 또는 자동화된 조치 목록\n");
        contextBuilder.append("3. 각 조치의 예상 결과\n");
        contextBuilder.append("4. 최종 요약 및 다음 단계\n");

        return contextBuilder.toString();
    }
    
    /**
     * SOAR 쿼리 변환기
     */
    private static class SoarQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public SoarQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                보안 인시던트 대응을 위한 검색 쿼리를 최적화하세요:
                
                원본 쿼리: %s
                
                최적화 지침:
                1. 보안 위협 지표(IOC)를 포함하세요
                2. MITRE ATT&CK 프레임워크 용어를 추가하세요
                3. 관련 CVE, CWE 참조를 포함하세요
                4. 위협 액터 및 캠페인 이름을 포함하세요
                5. 시간적 컨텍스트를 명확히 하세요
                
                최적화된 쿼리만 반환하세요.
                """, originalQuery.text());
            
            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();
                
            return new Query(transformedText);
        }
    }

    private String getDefaultContext() {
        return """
        ## 기본 SOAR 컨텍스트
        
        SOAR 분석을 위한 충분한 데이터가 없습니다.
        기본적인 인시던트 대응 절차를 따릅니다.
        """;
    }
}