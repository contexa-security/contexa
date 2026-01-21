package io.contexa.contexacoreenterprise.soar.retriever;

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

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
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
        
        if (chatClientBuilder != null) {
            createSoarAdvisor();
        }

        registry.registerRetriever(SoarContext.class, this);
            }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof SoarContext) {
            return retrieveSoarContextWithRAG((AIRequest<SoarContext>) request);
        }
        return super.retrieveContext(request);
    }

    private void createSoarAdvisor() {
        
        QueryTransformer soarQueryTransformer = new SoarQueryTransformer(chatClientBuilder);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType",
                "incident",  
                VectorDocumentType.THREAT.getValue(),
                "security_alert",  
                "soar_playbook"),  
            filterBuilder.gte("severity", 0.5)
        ).build();

        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(soarSimilarityThreshold)
            .topK(soarTopK)
            .filterExpression(filter)
            .build();

        soarAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(soarQueryTransformer)
            .build();

        registerDomainAdvisor(SoarContext.class, soarAdvisor);
    }

    private ContextRetrievalResult retrieveSoarContextWithRAG(AIRequest<SoarContext> request) {
        
        try {
            
            ContextRetrievalResult baseResult = super.retrieveContext(request);
            
            SoarContext context = request.getContext();

            String enhancedContext = buildComprehensiveContext(
                context, 
                baseResult.getContextInfo(),
                baseResult.getDocuments()
            );

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

    private List<Document> searchSecurityKnowledge(SoarContext context) {
        
        String searchQuery = buildSearchQuery(context);

        SearchRequest searchRequest = SearchRequest.builder()
                .query(searchQuery)
                .topK(5)  
                .similarityThreshold(0.7)  
                .build();

        List<Document> documents = vectorStore.similaritySearch(searchRequest);

        return documents;
    }

    private String buildSearchQuery(SoarContext context) {
        StringBuilder query = new StringBuilder();

        if (context.getThreatType() != null) {
            query.append(context.getThreatType()).append(" ");
        }

        if (context.getDescription() != null) {
            query.append(context.getDescription()).append(" ");
        }

        if (context.getQueryIntent() != null) {
            query.append(context.getQueryIntent()).append(" ");
        }

        if (!context.getExtractedEntities().isEmpty()) {
            query.append(context.getExtractedEntities().values()).append(" ");
        }

        return query.toString().trim();
    }

    private String extractRagContext(List<Document> documents) {
        if (documents.isEmpty()) {
            return "";
        }

        return documents.stream()
                .map(doc -> {
                    String content = doc.getText();
                    
                    if (doc.getMetadata() != null && !doc.getMetadata().isEmpty()) {
                        String source = doc.getMetadata().getOrDefault("source", "unknown").toString();
                        return String.format("[출처: %s]\n%s", source, content);
                    }
                    return content;
                })
                .collect(Collectors.joining("\n\n"));
    }

    private String buildComprehensiveContext(SoarContext context, String baseContext, List<Document> documents) {
        String ragContext = extractRagContext(documents);
        StringBuilder contextBuilder = new StringBuilder();

        contextBuilder.append("## SOAR 분석 컨텍스트\n\n");

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

        if (ragContext != null && !ragContext.trim().isEmpty()) {
            contextBuilder.append("### 관련 보안 지식 (RAG)\n");
            contextBuilder.append(ragContext);
            contextBuilder.append("\n\n");
        }

        contextBuilder.append("### AI 분석 가이드\n");
        contextBuilder.append("위의 정보를 종합하여 다음을 평가하고 자동화된 조치를 제안해주세요:\n");
        contextBuilder.append("1. 인시던트의 심각도 재평가\n");
        contextBuilder.append("2. 실행할 플레이북 또는 자동화된 조치 목록\n");
        contextBuilder.append("3. 각 조치의 예상 결과\n");
        contextBuilder.append("4. 최종 요약 및 다음 단계\n");

        return contextBuilder.toString();
    }

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