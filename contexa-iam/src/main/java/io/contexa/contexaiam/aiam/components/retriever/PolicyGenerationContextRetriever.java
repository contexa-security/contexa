package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.aiam.labs.policy.PolicyGenerationVectorService;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
public class PolicyGenerationContextRetriever extends ContextRetriever {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ContextRetrieverRegistry contextRetrieverRegistry;
    private final PolicyGenerationVectorService vectorService;
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;
    
    @Value("${spring.ai.rag.policy.similarity-threshold:0.75}")
    private double policySimilarityThreshold;
    
    @Value("${spring.ai.rag.policy.top-k:15}")
    private int policyTopK;
    
    private RetrievalAugmentationAdvisor policyAdvisor;

    public PolicyGenerationContextRetriever(
            VectorStore vectorStore,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            ConditionTemplateRepository conditionTemplateRepository,
            ContextRetrieverRegistry contextRetrieverRegistry,
            PolicyGenerationVectorService vectorService) {
        super(vectorStore);
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.conditionTemplateRepository = conditionTemplateRepository;
        this.contextRetrieverRegistry = contextRetrieverRegistry;
        this.vectorService = vectorService;
    }

    
    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        log.info("ApplicationContext refreshed. Initializing PolicyGenerationContextRetriever...");
        registerSelf();
    }

    private void registerSelf() {
        
        if (chatClientBuilder != null && vectorStore != null) {
            createPolicyAdvisor();
        }

        contextRetrieverRegistry.registerRetriever(PolicyContext.class, this);
        log.info("PolicyGenerationContextRetriever 자동 등록 완료 (Spring AI RAG 지원)");
    }
    
    
    private void createPolicyAdvisor() {
        
        QueryTransformer policyQueryTransformer = new PolicyQueryTransformer(chatClientBuilder);
        
        
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType", "policy", "rule", "rbac", "abac", "permission"),
            filterBuilder.gte("relevanceScore", 0.7)
        ).build();
        
        
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(policySimilarityThreshold)
            .topK(policyTopK)
            .filterExpression(filter)
            .build();
        
        
        policyAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(policyQueryTransformer)
            .build();
        
        
        registerDomainAdvisor(PolicyContext.class, policyAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        log.debug("PolicyGenerationContextRetriever.retrieveContext 호출됨");
        
        
        if (request.getContext() instanceof PolicyContext) {
            
            ContextRetrievalResult ragResult = null;
            if (policyAdvisor != null) {
                ragResult = super.retrieveContext(request);
            }
            
            String contextInfo = retrievePolicyGenerationContext(
                (AIRequest<PolicyContext>) request,
                ragResult != null ? ragResult.getDocuments() : List.of()
            );
            
            Map<String, Object> metadata = new HashMap<>();
            if (ragResult != null) {
                metadata.putAll(ragResult.getMetadata());
            }
            metadata.put("retrieverType", "PolicyGenerationContextRetriever");
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("ragEnabled", policyAdvisor != null);
            
            return new ContextRetrievalResult(
                contextInfo,
                ragResult != null ? ragResult.getDocuments() : List.of(),
                metadata
            );
        }
        
        
        return super.retrieveContext(request);
    }

    
    public String retrievePolicyGenerationContext(AIRequest<PolicyContext> request, List<Document> ragDocuments) {
        log.info("정책 생성 컨텍스트 검색 시작: {}", request.getRequestId());

        try {
            
            String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
            if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
                log.warn("naturalLanguageQuery 파라미터가 없습니다");
                return buildSystemMetadata(null);
            }
            
            
            try {
                PolicyContext context = request.getContext();
                if (context != null) {
                    vectorService.storePolicyRequest(context);
                    log.debug("💾 VectorService에 정책 요청 저장 완료");
                }
            } catch (Exception e) {
                log.warn("VectorService 정책 요청 저장 실패: {}", e.getMessage());
            }

            
            List<Document> similarPolicies = List.of();
            try {
                similarPolicies = vectorService.findSimilarPolicies(naturalLanguageQuery, 5);
                log.debug("VectorService에서 {}개의 유사 정책 발견", similarPolicies.size());
            } catch (Exception e) {
                log.warn("VectorService 정책 검색 실패: {}", e.getMessage());
            }
            
            
            List<Document> allDocuments = new ArrayList<>();
            allDocuments.addAll(similarPolicies);
            
            if (ragDocuments != null && !ragDocuments.isEmpty()) {
                for (Document doc : ragDocuments) {
                    boolean isDuplicate = allDocuments.stream()
                        .anyMatch(existing -> existing.getText().equals(doc.getText()));
                    if (!isDuplicate) {
                        allDocuments.add(doc);
                    }
                }
            }
            
            String contextInfo = "";
            if (!allDocuments.isEmpty()) {
                contextInfo = allDocuments.stream()
                        .map(doc -> "- " + doc.getText())
                        .collect(Collectors.joining("\n"));
            }

            
            PolicyGenerationItem.AvailableItems availableItems =
                request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class);

            
            String systemMetadata = buildSystemMetadata(availableItems);
            
            
            StringBuilder combinedContext = new StringBuilder();
            
            
            combinedContext.append("시스템 정보:\n")
                          .append(systemMetadata)
                          .append("\n\n");

            
            if (!contextInfo.trim().isEmpty()) {
                combinedContext.append("**참고 컨텍스트:**\n")
                              .append(contextInfo)
                              .append("\n");
            }

            String result = combinedContext.toString();
            log.info("정책 생성 컨텍스트 검색 완료 - 길이: {}, 문서: {}개", 
                    result.length(), allDocuments.size());
            
            
            try {
                vectorService.storePolicyResult(request.getRequestId(), result);
                log.debug("💾 VectorService에 정책 결과 저장 완료");
            } catch (Exception e) {
                log.warn("VectorService 정책 결과 저장 실패: {}", e.getMessage());
            }
            
            return result;

        } catch (Exception e) {
            log.error("정책 생성 컨텍스트 검색 실패", e);
            
            return buildSystemMetadata(null);
        }
    }

    
    private String buildSystemMetadata(PolicyGenerationItem.AvailableItems availableItems) {
        StringBuilder metadata = new StringBuilder();

        if (availableItems != null) {
            
            metadata.append("현재 사용 가능한 항목들 (반드시 이 ID들만 사용하세요):\n\n");
            
            
            if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
                metadata.append("사용 가능한 역할:\n");
                availableItems.roles().forEach(role ->
                        metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n", 
                            role.id(), role.name(), role.description() != null ? role.description() : "")));
            } else {
                metadata.append("사용 가능한 역할: 없음\n");
            }

            
            if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
                metadata.append("\n🔑 사용 가능한 권한:\n");
                availableItems.permissions().forEach(perm ->
                        metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n", 
                            perm.id(), perm.name(), perm.description() != null ? perm.description() : "")));
            } else {
                metadata.append("\n🔑 사용 가능한 권한: 없음\n");
            }

            
            if (availableItems.conditions() != null && !availableItems.conditions().isEmpty()) {
                metadata.append("\n⏰ 사용 가능한 조건 템플릿:\n");
                availableItems.conditions().forEach(cond ->
                        metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s, 호환가능: %s\n", 
                            cond.id(), cond.name(), 
                            cond.description() != null ? cond.description() : "",
                            cond.isCompatible() != null ? cond.isCompatible() : true)));
            } else {
                metadata.append("\n⏰ 사용 가능한 조건 템플릿: 없음\n");
            }
            
            metadata.append("\n경고: 위에 나열된 ID들 외의 다른 ID는 절대 사용하지 마세요. 존재하지 않는 ID를 사용하면 시스템 오류가 발생합니다.\n");
            
        } else {
            
            log.info("availableItems가 null, DB에서 모든 항목 조회");
            
            
            List<Role> roles = roleRepository.findAll();
            metadata.append("사용 가능한 역할:\n");
            roles.forEach(role ->
                    metadata.append(String.format("- ID: %d, 이름: %s\n", role.getId(), role.getRoleName())));

            
            List<Permission> permissions = permissionRepository.findAll();
            metadata.append("\n🔑 사용 가능한 권한:\n");
            permissions.forEach(perm ->
                    metadata.append(String.format("- ID: %d, 이름: %s\n", perm.getId(), perm.getFriendlyName())));

            
            List<ConditionTemplate> conditions = conditionTemplateRepository.findAll();
            metadata.append("\n⏰ 사용 가능한 조건 템플릿:\n");
            conditions.forEach(cond ->
                    metadata.append(String.format("- ID: %d, 이름: %s\n", cond.getId(), cond.getName())));
        }

        log.debug("생성된 시스템 메타데이터 길이: {}", metadata.length());
        return metadata.toString();
    }
    
    
    private static class PolicyQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public PolicyQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                정책 생성을 위한 검색 쿼리를 최적화하세요:
                
                원본 쿼리: %s
                
                최적화 지침:
                1. RBAC, ABAC 같은 접근 제어 패턴을 포함하세요
                2. 역할, 권한, 조건 같은 정책 구성 요소를 추가하세요
                3. 비지니스 규칙과 컴플라이언스 관련 용어를 포함하세요
                4. 보안 정책 패턴과 베스트 프랙티스를 추가하세요
                5. 조직 계층 및 업무 분리 관련 키워드를 포함하세요
                
                최적화된 쿼리만 반환하세요.
                """, originalQuery.text());
            
            String transformedText = chatClient.prompt()
                .user(prompt)
                .call()
                .content();
                
            return new Query(transformedText);
        }
    }
} 