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
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 정책 생성 컨텍스트 검색기 - 구버전 완전 이식
 * 
 * ConditionTemplateContextRetriever와 동일한 패턴 적용:
 * - RAG 검색 (VectorStore)
 * - 시스템 메타데이터 구성 (buildSystemMetadata)
 * - ContextRetrieverRegistry 자동 등록
 * 
 * 역할:
 * 1. RAG 기반 관련 문서 검색
 * 2. availableItems 기반 시스템 메타데이터 구성
 * 3. 컨텍스트 정보 조합 및 반환
 */
@Slf4j
@Component
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

    /**
     * Spring ApplicationContext가 완전히 초기화된 후 호출됩니다.
     * ServletContext, JPA EntityManager, BeanPostProcessor 등이 모두 준비된 상태에서 실행됩니다.
     *
     * @param event ContextRefreshedEvent
     */
    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        log.info("ApplicationContext refreshed. Initializing PolicyGenerationContextRetriever...");
        registerSelf();
    }

    private void registerSelf() {
        // RAG Advisor 생성 (사용 가능한 경우)
        if (chatClientBuilder != null && vectorStore != null) {
            createPolicyAdvisor();
        }

        contextRetrieverRegistry.registerRetriever(PolicyContext.class, this);
        log.info("PolicyGenerationContextRetriever 자동 등록 완료 (Spring AI RAG 지원)");
    }
    
    /**
     * 정책 생성 전용 RAG Advisor 생성
     */
    private void createPolicyAdvisor() {
        // 정책 쿼리 변환기
        QueryTransformer policyQueryTransformer = new PolicyQueryTransformer(chatClientBuilder);
        
        // 정책 필터 구성
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType", "policy", "rule", "rbac", "abac", "permission"),
            filterBuilder.gte("relevanceScore", 0.7)
        ).build();
        
        // VectorStoreDocumentRetriever 구성
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(policySimilarityThreshold)
            .topK(policyTopK)
            .filterExpression(filter)
            .build();
        
        // Policy RAG Advisor 생성
        policyAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(policyQueryTransformer)
            .build();
        
        // 부모 클래스에 Advisor 등록
        registerDomainAdvisor(PolicyContext.class, policyAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        log.debug("PolicyGenerationContextRetriever.retrieveContext 호출됨");
        
        // PolicyContext 타입인 경우 특화 처리
        if (request.getContext() instanceof PolicyContext) {
            // RAG 기반 검색 시도
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
        
        // 그 외의 경우 상위 클래스의 기본 처리
        return super.retrieveContext(request);
    }

    /**
     * 정책 생성 컨텍스트 검색 (구버전 generatePolicyFromTextStream 로직 완전 이식)
     */
    public String retrievePolicyGenerationContext(AIRequest<PolicyContext> request, List<Document> ragDocuments) {
        log.info("정책 생성 컨텍스트 검색 시작: {}", request.getRequestId());

        try {
            // 1. 자연어 쿼리 추출
            String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
            if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
                log.warn("naturalLanguageQuery 파라미터가 없습니다");
                return buildSystemMetadata(null);
            }
            
            // VectorService에 정책 요청 저장
            try {
                PolicyContext context = request.getContext();
                if (context != null) {
                    vectorService.storePolicyRequest(context);
                    log.debug("💾 VectorService에 정책 요청 저장 완료");
                }
            } catch (Exception e) {
                log.warn("VectorService 정책 요청 저장 실패: {}", e.getMessage());
            }

            // 2. VectorService를 통한 유사 정책 패턴 검색
            List<Document> similarPolicies = List.of();
            try {
                similarPolicies = vectorService.findSimilarPolicies(naturalLanguageQuery, 5);
                log.debug("VectorService에서 {}개의 유사 정책 발견", similarPolicies.size());
            } catch (Exception e) {
                log.warn("VectorService 정책 검색 실패: {}", e.getMessage());
            }
            
            // 3. RAG 기반 검색 결과와 병합
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

            // 3. 사용 가능한 항목들 추출 (파라미터에서)
            PolicyGenerationItem.AvailableItems availableItems =
                request.getParameter("availableItems", PolicyGenerationItem.AvailableItems.class);

            // 4. 시스템 메타데이터 구성 (구버전 buildSystemMetadata 로직 완전 이식)
            String systemMetadata = buildSystemMetadata(availableItems);
            
            // 5. 컨텍스트 조합
            StringBuilder combinedContext = new StringBuilder();
            
            // 시스템 메타데이터 (구버전 방식)
            combinedContext.append("시스템 정보:\n")
                          .append(systemMetadata)
                          .append("\n\n");

            // RAG 컨텍스트 (있는 경우만)
            if (!contextInfo.trim().isEmpty()) {
                combinedContext.append("**참고 컨텍스트:**\n")
                              .append(contextInfo)
                              .append("\n");
            }

            String result = combinedContext.toString();
            log.info("정책 생성 컨텍스트 검색 완료 - 길이: {}, 문서: {}개", 
                    result.length(), allDocuments.size());
            
            // VectorService에 정책 결과 저장
            try {
                vectorService.storePolicyResult(request.getRequestId(), result);
                log.debug("💾 VectorService에 정책 결과 저장 완료");
            } catch (Exception e) {
                log.warn("VectorService 정책 결과 저장 실패: {}", e.getMessage());
            }
            
            return result;

        } catch (Exception e) {
            log.error("정책 생성 컨텍스트 검색 실패", e);
            // 폴백: 기본 시스템 메타데이터만 반환
            return buildSystemMetadata(null);
        }
    }

    /**
     * availableItems 기반 시스템 메타데이터 구성
     */
    private String buildSystemMetadata(PolicyGenerationItem.AvailableItems availableItems) {
        StringBuilder metadata = new StringBuilder();

        if (availableItems != null) {
            // 프론트엔드에서 제공된 사용 가능한 항목들 사용
            metadata.append("현재 사용 가능한 항목들 (반드시 이 ID들만 사용하세요):\n\n");
            
            // 역할 정보
            if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
                metadata.append("사용 가능한 역할:\n");
                availableItems.roles().forEach(role ->
                        metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n", 
                            role.id(), role.name(), role.description() != null ? role.description() : "")));
            } else {
                metadata.append("사용 가능한 역할: 없음\n");
            }

            // 권한 정보
            if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
                metadata.append("\n🔑 사용 가능한 권한:\n");
                availableItems.permissions().forEach(perm ->
                        metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n", 
                            perm.id(), perm.name(), perm.description() != null ? perm.description() : "")));
            } else {
                metadata.append("\n🔑 사용 가능한 권한: 없음\n");
            }

            // 조건 템플릿 정보
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
            // 기존 방식: DB에서 모든 항목 조회 (구버전과 완전히 동일)
            log.info("availableItems가 null, DB에서 모든 항목 조회");
            
            // 역할 정보
            List<Role> roles = roleRepository.findAll();
            metadata.append("사용 가능한 역할:\n");
            roles.forEach(role ->
                    metadata.append(String.format("- ID: %d, 이름: %s\n", role.getId(), role.getRoleName())));

            // 권한 정보
            List<Permission> permissions = permissionRepository.findAll();
            metadata.append("\n🔑 사용 가능한 권한:\n");
            permissions.forEach(perm ->
                    metadata.append(String.format("- ID: %d, 이름: %s\n", perm.getId(), perm.getFriendlyName())));

            // 조건 템플릿 정보
            List<ConditionTemplate> conditions = conditionTemplateRepository.findAll();
            metadata.append("\n⏰ 사용 가능한 조건 템플릿:\n");
            conditions.forEach(cond ->
                    metadata.append(String.format("- ID: %d, 이름: %s\n", cond.getId(), cond.getName())));
        }

        log.debug("생성된 시스템 메타데이터 길이: {}", metadata.length());
        return metadata.toString();
    }
    
    /**
     * 정책 쿼리 변환기
     */
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