package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.advisor.RetrievalAugmentationAdvisor;
import org.springframework.ai.rag.preretrieval.query.transformation.QueryTransformer;
import org.springframework.ai.rag.retrieval.search.VectorStoreDocumentRetriever;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class StudioQueryContextRetriever extends ContextRetriever {

    private final VectorStore vectorStore;
    private final ContextRetrieverRegistry registry;
    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final StudioQueryVectorService vectorService;

    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;

    @Value("${spring.ai.rag.studio.similarity-threshold:0.65}")
    private double studioSimilarityThreshold;

    @Value("${spring.ai.rag.studio.top-k:10}")
    private int studioTopK;

    private RetrievalAugmentationAdvisor studioAdvisor;

    public StudioQueryContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            StudioQueryVectorService vectorService) {
        super(vectorStore);
        this.vectorStore = vectorStore;
        this.registry = registry;
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.vectorService = vectorService;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        registerSelf();
    }

    private void registerSelf() {

        if (chatClientBuilder != null && vectorStore != null) {
            createStudioAdvisor();
        }

        registry.registerRetriever(StudioQueryContext.class, this);
    }

    private void createStudioAdvisor() {

        QueryTransformer studioQueryTransformer = new StudioQueryTransformer(chatClientBuilder);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
                filterBuilder.in("documentType", "authorization", "query", "studio", "access"),
                filterBuilder.gte("relevanceScore", 0.6)
        ).build();

        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
                .vectorStore(vectorStore)
                .similarityThreshold(studioSimilarityThreshold)
                .topK(studioTopK)
                .filterExpression(filter)
                .build();

        studioAdvisor = RetrievalAugmentationAdvisor.builder()
                .documentRetriever(retriever)
                .queryTransformers(studioQueryTransformer)
                .build();

        registerDomainAdvisor(StudioQueryContext.class, studioAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {

        if (request.getContext() instanceof StudioQueryContext) {
            String contextInfo = retrieveStudioQueryContext((AIRequest<StudioQueryContext>) request);
            return new ContextRetrievalResult(
                    contextInfo,
                    List.of(),
                    Map.of("retrieverType", "StudioQueryContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }

        return super.retrieveContext(request);
    }

    public String retrieveStudioQueryContext(AIRequest<StudioQueryContext> request) {

        try {
            StudioQueryContext context = request.getContext();
            StringBuilder contextBuilder = new StringBuilder();

            String naturalQuery = request.getNaturalLanguageQuery();
            if (naturalQuery == null || naturalQuery.trim().isEmpty()) {
                log.warn("자연어 질의가 비어있습니다");
                return getDefaultStudioQueryContext();
            }

            try {
                vectorService.storeQuery(naturalQuery);
            } catch (Exception e) {
                log.warn("VectorService query save failed: {}", e.getMessage());
            }

            String similarQueryPatterns = searchSimilarQueryPatterns(naturalQuery);
            if (!similarQueryPatterns.isEmpty()) {
                contextBuilder.append("## [Similar Query Pattern Analysis]\n");
                contextBuilder.append(similarQueryPatterns).append("\n\n");
            }

            String authorizationStructure = buildAuthorizationStructure(context);
            contextBuilder.append("## [Current Authorization Structure]\n");
            contextBuilder.append(authorizationStructure).append("\n\n");

            String mappingInfo = buildUserGroupRolePermissionMapping(context);
            contextBuilder.append("## [Permission Mapping Information]\n");
            contextBuilder.append(mappingInfo).append("\n\n");

            String analysisGuidelines = getQueryTypeGuidelines(context);
            contextBuilder.append("## 분석 가이드라인\n");
            contextBuilder.append(analysisGuidelines);

            String result = contextBuilder.toString();

            try {
                String queryId = request.getRequestId();
                vectorService.storeQueryResult(queryId, result);
            } catch (Exception e) {
                log.warn("VectorService 결과 저장 실패: {}", e.getMessage());
            }

            return result;

        } catch (Exception e) {
            log.error("Studio Query 컨텍스트 검색 실패", e);
            return getDefaultStudioQueryContext();
        }
    }

    private String searchSimilarQueryPatterns(String naturalQuery) {
        try {

            List<Document> similarQueries = vectorService.findSimilarQueries(naturalQuery, 5);

            String searchQuery = String.format("Authorization Studio 질의: %s", naturalQuery);
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(searchQuery)
                    .topK(3)
                    .similarityThreshold(0.6)
                    .build();
            List<Document> vectorDocs = vectorStore.similaritySearch(searchRequest);

            List<Document> allDocs = new ArrayList<>();
            allDocs.addAll(similarQueries);

            for (Document doc : vectorDocs) {
                boolean isDuplicate = allDocs.stream()
                        .anyMatch(existing -> existing.getText().equals(doc.getText()));
                if (!isDuplicate) {
                    allDocs.add(doc);
                }
            }

            if (allDocs.isEmpty()) {
                return "";
            }

            StringBuilder patterns = new StringBuilder();
            patterns.append("### 유사 질의 사례:\n");

            for (int i = 0; i < Math.min(allDocs.size(), 8); i++) {
                Document doc = allDocs.get(i);
                patterns.append(String.format("%d. %s\n", i + 1, doc.getText()));

                if (doc.getMetadata().containsKey("queryType")) {
                    patterns.append("   - 질의 타입: ").append(doc.getMetadata().get("queryType")).append("\n");
                }
                if (doc.getMetadata().containsKey("resultSummary")) {
                    patterns.append("   - 결과 요약: ").append(doc.getMetadata().get("resultSummary")).append("\n");
                }
                if (doc.getMetadata().containsKey("confidence")) {
                    patterns.append("   - 신뢰도: ").append(doc.getMetadata().get("confidence")).append("\n");
                }
            }

            return patterns.toString();

        } catch (Exception e) {
            log.warn("RAG 유사 질의 검색 실패: {}", e.getMessage());
            return "";
        }
    }

    private String buildAuthorizationStructure(StudioQueryContext context) {
        StringBuilder structure = new StringBuilder();

        try {

            long totalUsers = userRepository.count();
            structure.append(String.format("- 전체 사용자 수: %d명\n", totalUsers));

            long totalGroups = groupRepository.count();
            structure.append(String.format("- 전체 그룹 수: %d개\n", totalGroups));

            long totalRoles = roleRepository.count();
            structure.append(String.format("- 전체 역할 수: %d개\n", totalRoles));

            long totalPermissions = permissionRepository.count();
            structure.append(String.format("- 전체 권한 수: %d개\n", totalPermissions));

            List<Group> topGroups = groupRepository.findAll().stream()
                    .limit(10)
                    .collect(Collectors.toList());

            if (!topGroups.isEmpty()) {
                structure.append("### 주요 그룹:\n");
                topGroups.forEach(group -> {
                    structure.append(String.format("- %s (ID: %d)\n", group.getName(), group.getId()));
                });
                structure.append("\n");
            }

            List<Role> topRoles = roleRepository.findAll().stream()
                    .limit(10)
                    .collect(Collectors.toList());

            if (!topRoles.isEmpty()) {
                structure.append("### 주요 역할:\n");
                topRoles.forEach(role -> {
                    structure.append(String.format("- %s (ID: %d)\n", role.getRoleName(), role.getId()));
                });
                structure.append("\n");
            }

            List<Permission> topPermissions = permissionRepository.findAll().stream()
                    .limit(15)
                    .collect(Collectors.toList());

            if (!topPermissions.isEmpty()) {
                structure.append("### 주요 권한:\n");
                topPermissions.forEach(perm -> {
                    structure.append(String.format("- %s (%s)\n",
                            perm.getFriendlyName(), perm.getManagedResource().getResourceIdentifier()));
                });
            }

        } catch (Exception e) {
            log.warn("권한 구조 정보 구성 실패: {}", e.getMessage());
            structure.append("권한 구조 정보를 가져오는 중 오류가 발생했습니다.\n");
        }

        return structure.toString();
    }

    private String buildUserGroupRolePermissionMapping(StudioQueryContext context) {
        StringBuilder mapping = new StringBuilder();

        try {

            List<Users> sampleUsers = userRepository.findAllWithDetails().stream()
                    .limit(5)
                    .collect(Collectors.toList());

            if (!sampleUsers.isEmpty()) {
                mapping.append("### 사용자별 권한 구조 샘플:\n");

                for (Users user : sampleUsers) {
                    mapping.append(String.format("\n#### %s (ID: %d):\n", user.getName(), user.getId()));

                    Set<UserGroup> userGroups = user.getUserGroups();
                    if (userGroups != null && !userGroups.isEmpty()) {
                        mapping.append("- 소속 그룹: ");
                        String groupNames = userGroups.stream()
                                .map(ug -> ug.getGroup().getName())
                                .collect(Collectors.joining(", "));
                        mapping.append(groupNames).append("\n");
                    }

                    Set<Role> userRoles = getUserRolesFromGroups(user);
                    if (!userRoles.isEmpty()) {
                        mapping.append("- 보유 역할: ");
                        String roleNames = userRoles.stream()
                                .map(Role::getRoleName)
                                .collect(Collectors.joining(", "));
                        mapping.append(roleNames).append("\n");
                    }

                    Set<Permission> userPermissions = getPermissionsFromRoles(userRoles);
                    if (!userPermissions.isEmpty()) {
                        mapping.append("- 보유 권한: ");
                        String permissionNames = userPermissions.stream()
                                .map(Permission::getFriendlyName)
                                .limit(10)
                                .collect(Collectors.joining(", "));
                        mapping.append(permissionNames);
                        if (userPermissions.size() > 10) {
                            mapping.append(String.format(" 외 %d개", userPermissions.size() - 10));
                        }
                        mapping.append("\n");
                    }
                }
            }

            mapping.append("\n### 그룹별 역할 매핑:\n");
            List<Group> sampleGroups = groupRepository.findAllWithRolesAndPermissions().stream()
                    .limit(5)
                    .collect(Collectors.toList());

            for (Group group : sampleGroups) {
                mapping.append(String.format("- %s: ", group.getName()));

                Set<GroupRole> groupRoles = group.getGroupRoles();
                if (groupRoles != null && !groupRoles.isEmpty()) {
                    String roleNames = groupRoles.stream()
                            .map(gr -> gr.getRole().getRoleName())
                            .collect(Collectors.joining(", "));
                    mapping.append(roleNames);
                } else {
                    mapping.append("역할 없음");
                }
                mapping.append("\n");
            }

        } catch (Exception e) {
            log.warn("매핑 정보 구성 실패: {}", e.getMessage());
            mapping.append("매핑 정보를 가져오는 중 오류가 발생했습니다.\n");
        }

        return mapping.toString();
    }

    private Set<Role> getUserRolesFromGroups(Users user) {
        Set<Role> roles = new HashSet<>();
        if (user.getUserGroups() != null) {
            for (UserGroup userGroup : user.getUserGroups()) {
                Group group = userGroup.getGroup();
                if (group != null && group.getGroupRoles() != null) {
                    for (GroupRole groupRole : group.getGroupRoles()) {
                        if (groupRole.getRole() != null) {
                            roles.add(groupRole.getRole());
                        }
                    }
                }
            }
        }
        return roles;
    }

    private Set<Permission> getPermissionsFromRoles(Set<Role> roles) {
        Set<Permission> permissions = new HashSet<>();
        for (Role role : roles) {
            if (role.getRolePermissions() != null) {
                for (RolePermission rolePermission : role.getRolePermissions()) {
                    if (rolePermission.getPermission() != null) {
                        permissions.add(rolePermission.getPermission());
                    }
                }
            }
        }
        return permissions;
    }

    private String getQueryTypeGuidelines(StudioQueryContext context) {

        return "### 분석 지침:\n" +
                """
                        - 특정 작업을 수행할 수 있는 모든 사용자 식별
                        - 직접 권한과 그룹/역할을 통한 간접 권한 모두 확인
                        - 권한 획득 경로 명확히 표시
                        
                        - 시각화: 사용자 → 그룹 → 역할 → 권한 흐름도
                        - 접근 불가 원인을 단계별로 분석
                        - 필요한 권한과 현재 보유 권한 비교
                        - 권한 획득을 위한 구체적 방법 제시
                        
                        - 시각화: 현재 상태와 필요 상태 비교 다이어그램
                        - 대상의 전체 권한 구조 상세 분석
                        - 권한의 출처(직접/간접) 구분
                        - 과도한 권한이나 부족한 권한 식별
                        
                        - 시각화: 권한 계층 구조도
                        - 질의에 가장 적합한 분석 방법 선택
                        - 명확하고 실행 가능한 답변 제공
                        - 보안 관점에서의 권장사항 포함
                        - 적절한 시각화 방법 선택
                        """;
    }

    private String getDefaultStudioQueryContext() {
        return """
                ## 기본 Authorization Studio 컨텍스트
                
                ### 지원하는 질의 유형:
                - "누가 ~할 수 있나요?" (WHO_CAN)
                - "왜 ~할 수 없나요?" (WHY_CANNOT)
                - "~의 권한을 분석해주세요" (ANALYZE_PERMISSIONS)
                - "~에 접근하는 경로는?" (ACCESS_PATH)
                - "~변경 시 영향은?" (IMPACT_ANALYSIS)
                
                ### 분석 원칙:
                - 정확한 데이터 기반 분석
                - 권한 획득 경로 명확히 표시
                - 보안 관점의 권장사항 제공
                - 직관적인 시각화 제공
                
                ### 주의사항:
                - 민감한 정보는 필터링
                - 최소 권한 원칙 준수
                - 컴플라이언스 고려
                """;
    }

    private static class StudioQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;

        public StudioQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }

        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }

            String prompt = String.format("""
                    Authorization Studio 자연어 질의를 위한 검색 쿼리를 최적화하세요:
                    
                    원본 쿼리: %s
                    
                    최적화 지침:
                    1. 사용자, 그룹, 역할, 권한 관련 용어를 추가하세요
                    2. 접근 경로와 권한 상속 관련 키워드를 포함하세요
                    3. WHO_CAN, WHY_CANNOT 등 질의 타입을 구체화하세요
                    4. 조직 구조와 계층 관계 관련 용어를 추가하세요
                    5. 권한 분석과 영향 평가 관련 키워드를 포함하세요
                    
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