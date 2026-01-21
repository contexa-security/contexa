package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.AccessGovernanceContext;
import io.contexa.contexaiam.aiam.labs.accessGovernance.AccessVectorService;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.Users;
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
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class AccessGovernanceContextRetriever extends ContextRetriever {

    private final ContextRetrieverRegistry registry;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final GroupRepository groupRepository;
    private final AccessVectorService vectorService;
    
    @Autowired(required = false)
    private ChatClient.Builder chatClientBuilder;
    
    @Value("${spring.ai.rag.governance.similarity-threshold:0.8}")
    private double governanceSimilarityThreshold;
    
    @Value("${spring.ai.rag.governance.top-k:15}")
    private int governanceTopK;
    
    private RetrievalAugmentationAdvisor governanceAdvisor;

    private static final int MAX_FINDINGS = 50;
    private static final double DORMANT_PERMISSION_THRESHOLD = 30; 
    private static final double EXCESSIVE_PERMISSION_THRESHOLD = 20; 
    private static final double SOD_VIOLATION_THRESHOLD = 0.8; 

    public AccessGovernanceContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            UserRepository userRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            GroupRepository groupRepository,
            AccessVectorService vectorService) {
        super(vectorStore);
        this.registry = registry;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.groupRepository = groupRepository;
        this.vectorService = vectorService;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
                registerSelf();
    }

    private void registerSelf() {
        
        if (chatClientBuilder != null && vectorStore != null) {
            createGovernanceAdvisor();
        }

        registry.registerRetriever(AccessGovernanceContext.class, this);
            }

    private void createGovernanceAdvisor() {
        
        QueryTransformer governanceQueryTransformer = new GovernanceQueryTransformer(chatClientBuilder);

        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType", "governance", "policy", "compliance", "audit"),
            filterBuilder.gte("relevanceScore", 0.7)
        ).build();

        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(governanceSimilarityThreshold)
            .topK(governanceTopK)
            .filterExpression(filter)
            .build();

        governanceAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(governanceQueryTransformer)
            .build();

        registerDomainAdvisor(AccessGovernanceContext.class, governanceAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof AccessGovernanceContext) {
            
            ContextRetrievalResult ragResult = null;
            if (governanceAdvisor != null) {
                ragResult = super.retrieveContext(request);
            }

            String contextInfo = retrieveAccessGovernanceContext(
                (AIRequest<AccessGovernanceContext>) request,
                ragResult != null ? ragResult.getDocuments() : List.of()
            );

            Map<String, Object> metadata = new HashMap<>();
            if (ragResult != null) {
                metadata.putAll(ragResult.getMetadata());
            }
            metadata.put("retrieverType", "AccessGovernanceContextRetriever");
            metadata.put("timestamp", System.currentTimeMillis());
            metadata.put("ragEnabled", governanceAdvisor != null);
            
            return new ContextRetrievalResult(
                    contextInfo,
                    ragResult != null ? ragResult.getDocuments() : List.of(),
                    metadata
            );
        }
        return super.retrieveContext(request);
    }

    public String retrieveAccessGovernanceContext(AIRequest<AccessGovernanceContext> request, List<Document> ragDocuments) {
        
        try {
            AccessGovernanceContext context = request.getContext();

            try {
                vectorService.storeGovernanceContext(context);
            } catch (Exception e) {
                log.error("벡터 저장소 컨텍스트 저장 실패", e);
            }

            PermissionMatrix permissionMatrix = collectPermissionMatrix(context);

            UserPermissionAnalysis userAnalysis = analyzeUserPermissions(context, permissionMatrix);

            RolePermissionAnalysis roleAnalysis = analyzeRolePermissions(context, permissionMatrix);

            GroupPermissionAnalysis groupAnalysis = analyzeGroupPermissions(context, permissionMatrix);

            AnomalyDetectionResult anomalyResult = detectAnomalies(context, permissionMatrix, userAnalysis, roleAnalysis, groupAnalysis);

            GovernanceScore governanceScore = calculateGovernanceScore(anomalyResult);

            List<Document> vectorServiceDocs = List.of();
            try {
                String query = String.format("거버넌스 분석: scope=%s, type=%s, 이상 징후=%d", 
                    context.getAuditScope(), context.getAnalysisType(), anomalyResult.getTotalAnomalies());
                vectorServiceDocs = vectorService.findSimilarGovernanceDocuments(query, 10);
                            } catch (Exception e) {
                log.error("벡터 서비스 검색 실패", e);
            }

            List<Document> allDocuments = new ArrayList<>();
            if (ragDocuments != null) {
                allDocuments.addAll(ragDocuments);
            }
            allDocuments.addAll(vectorServiceDocs);

            String comprehensiveContext = buildComprehensiveContext(
                    context, permissionMatrix, userAnalysis, roleAnalysis, groupAnalysis, 
                    anomalyResult, governanceScore, allDocuments);

            return comprehensiveContext;

        } catch (Exception e) {
            log.error("권한 거버넌스 분석 실패", e);
            return getDefaultContext();
        }
    }

    private PermissionMatrix collectPermissionMatrix(AccessGovernanceContext context) {
        
        PermissionMatrix matrix = new PermissionMatrix();

        List<Users> users = userRepository.findAll();
        for (Users user : users) {
            Map<String, Object> userPermissions = new HashMap<>();
            userPermissions.put("userId", user.getId());
            userPermissions.put("username", user.getUsername());
            userPermissions.put("roles", user.getRoleNames());
            userPermissions.put("permissions", user.getPermissionNames());
            userPermissions.put("groups", user.getUserGroups().stream().map(ug -> ug.getGroup().getName()).collect(Collectors.toList()));
            userPermissions.put("lastLoginTime", user.getLastMfaUsedAt()); 
            userPermissions.put("enabled", true); 
            
            matrix.getUserMatrix().put(user.getId().toString(), userPermissions);
        }

        List<Role> roles = roleRepository.findAll();
        for (Role role : roles) {
            Map<String, Object> rolePermissions = new HashMap<>();
            rolePermissions.put("roleId", role.getId());
            rolePermissions.put("roleName", role.getRoleName());
            rolePermissions.put("permissions", role.getRolePermissions().stream().map(rp -> rp.getPermission().getName()).collect(Collectors.toList()));
            rolePermissions.put("users", role.getGroupRoles().stream().flatMap(gr -> gr.getGroup().getUserGroups().stream()).map(ug -> ug.getUser().getUsername()).distinct().collect(Collectors.toList()));
            rolePermissions.put("description", role.getRoleDesc());
            
            matrix.getRoleMatrix().put(role.getId().toString(), rolePermissions);
        }

        List<Permission> permissions = permissionRepository.findAll();
        for (Permission permission : permissions) {
            Map<String, Object> permissionDetails = new HashMap<>();
            permissionDetails.put("permissionId", permission.getId());
            permissionDetails.put("permissionName", permission.getName());
            permissionDetails.put("friendlyName", permission.getFriendlyName());
            permissionDetails.put("description", permission.getDescription());
            permissionDetails.put("targetType", permission.getTargetType());
            permissionDetails.put("actionType", permission.getActionType());
            
            permissionDetails.put("roles", roleRepository.findAll().stream()
                .filter(role -> role.getRolePermissions().stream()
                    .anyMatch(rp -> rp.getPermission().getId().equals(permission.getId())))
                .map(Role::getRoleName)
                .collect(Collectors.toList()));
            permissionDetails.put("users", roleRepository.findAll().stream()
                .filter(role -> role.getRolePermissions().stream()
                    .anyMatch(rp -> rp.getPermission().getId().equals(permission.getId())))
                .flatMap(role -> role.getGroupRoles().stream())
                .flatMap(gr -> gr.getGroup().getUserGroups().stream())
                .map(ug -> ug.getUser().getUsername())
                .distinct()
                .collect(Collectors.toList()));
            
            matrix.getPermissionMatrix().put(permission.getId().toString(), permissionDetails);
        }

        return matrix;
    }

    private UserPermissionAnalysis analyzeUserPermissions(AccessGovernanceContext context, PermissionMatrix matrix) {
        
        UserPermissionAnalysis analysis = new UserPermissionAnalysis();
        analysis.setTotalUsers(matrix.getUserMatrix().size());

        for (Map.Entry<String, Map<String, Object>> entry : matrix.getUserMatrix().entrySet()) {
            String userId = entry.getKey();
            Map<String, Object> userData = entry.getValue();
            
            List<String> permissions = (List<String>) userData.get("permissions");
            List<String> roles = (List<String>) userData.get("roles");

            int permissionCount = permissions != null ? permissions.size() : 0;
            int roleCount = roles != null ? roles.size() : 0;
            
            analysis.getUserPermissionCounts().put(userId, permissionCount);
            analysis.getUserRoleCounts().put(userId, roleCount);

            if (permissionCount > EXCESSIVE_PERMISSION_THRESHOLD) {
                analysis.getExcessivePermissionUsers().add(userId);
            }

            LocalDateTime lastLoginTime = (LocalDateTime) userData.get("lastLoginTime");
            if (lastLoginTime != null && lastLoginTime.isBefore(LocalDateTime.now().minusDays((long) DORMANT_PERMISSION_THRESHOLD))) {
                analysis.getDormantUsers().add(userId);
            }
        }

        return analysis;
    }

    private RolePermissionAnalysis analyzeRolePermissions(AccessGovernanceContext context, PermissionMatrix matrix) {
        
        RolePermissionAnalysis analysis = new RolePermissionAnalysis();
        analysis.setTotalRoles(matrix.getRoleMatrix().size());

        for (Map.Entry<String, Map<String, Object>> entry : matrix.getRoleMatrix().entrySet()) {
            String roleId = entry.getKey();
            Map<String, Object> roleData = entry.getValue();
            
            @SuppressWarnings("unchecked")
            List<String> permissions = (List<String>) roleData.get("permissions");
            @SuppressWarnings("unchecked")
            List<String> users = (List<String>) roleData.get("users");

            int permissionCount = permissions != null ? permissions.size() : 0;
            int userCount = users != null ? users.size() : 0;
            
            analysis.getRolePermissionCounts().put(roleId, permissionCount);
            analysis.getRoleUserCounts().put(roleId, userCount);

            if (userCount == 0) {
                analysis.getUnusedRoles().add(roleId);
            }

            if (permissionCount > EXCESSIVE_PERMISSION_THRESHOLD) {
                analysis.getExcessivePermissionRoles().add(roleId);
            }
        }

        return analysis;
    }

    private GroupPermissionAnalysis analyzeGroupPermissions(AccessGovernanceContext context, PermissionMatrix matrix) {
        
        GroupPermissionAnalysis analysis = new GroupPermissionAnalysis();

        List<Group> groups = groupRepository.findAll();
        analysis.setTotalGroups(groups.size());

        for (Group group : groups) {
            
            int userCount = group.getUserGroups().size();
            analysis.getGroupUserCounts().put(group.getId().toString(), userCount);

            if (userCount == 0) {
                analysis.getEmptyGroups().add(group.getId().toString());
            }
        }

        return analysis;
    }

    private AnomalyDetectionResult detectAnomalies(AccessGovernanceContext context, PermissionMatrix matrix,
                                                  UserPermissionAnalysis userAnalysis, 
                                                  RolePermissionAnalysis roleAnalysis,
                                                  GroupPermissionAnalysis groupAnalysis) {
        
        AnomalyDetectionResult result = new AnomalyDetectionResult();

        result.setDormantPermissions(userAnalysis.getDormantUsers().size());

        result.setExcessivePermissions(userAnalysis.getExcessivePermissionUsers().size() + 
                                     roleAnalysis.getExcessivePermissionRoles().size());

        result.setUnusedRoles(roleAnalysis.getUnusedRoles().size());

        result.setEmptyGroups(groupAnalysis.getEmptyGroups().size());

        result.setSodViolations(detectSodViolations(matrix));

        result.setTotalAnomalies(result.getDormantPermissions() + result.getExcessivePermissions() + 
                               result.getUnusedRoles() + result.getEmptyGroups() + result.getSodViolations());

        return result;
    }

    private int detectSodViolations(PermissionMatrix matrix) {

        int highPrivilegeUsers = 0;
        
        for (Map<String, Object> userData : matrix.getUserMatrix().values()) {
            @SuppressWarnings("unchecked")
            List<String> permissions = (List<String>) userData.get("permissions");
            if (permissions != null && permissions.size() > 15) { 
                highPrivilegeUsers++;
            }
        }
        
        return highPrivilegeUsers;
    }

    private GovernanceScore calculateGovernanceScore(AnomalyDetectionResult anomalyResult) {
        
        GovernanceScore score = new GovernanceScore();

        double baseScore = 100.0;

        double deduction = anomalyResult.getDormantPermissions() * 2.0 +
                          anomalyResult.getExcessivePermissions() * 3.0 +
                          anomalyResult.getUnusedRoles() * 1.5 +
                          anomalyResult.getEmptyGroups() * 1.0 +
                          anomalyResult.getSodViolations() * 5.0;

        score.setOverallScore(Math.max(0, baseScore - deduction));

        if (score.getOverallScore() >= 80) {
            score.setRiskLevel("LOW");
        } else if (score.getOverallScore() >= 60) {
            score.setRiskLevel("MEDIUM");
        } else if (score.getOverallScore() >= 40) {
            score.setRiskLevel("HIGH");
        } else {
            score.setRiskLevel("CRITICAL");
        }

        return score;
    }

    private String buildComprehensiveContext(AccessGovernanceContext context, PermissionMatrix matrix,
                                           UserPermissionAnalysis userAnalysis, 
                                           RolePermissionAnalysis roleAnalysis,
                                           GroupPermissionAnalysis groupAnalysis,
                                           AnomalyDetectionResult anomalyResult,
                                           GovernanceScore governanceScore,
                                           List<Document> ragDocuments) {
        
        StringBuilder contextBuilder = new StringBuilder();
        
        contextBuilder.append("권한 거버넌스 분석 컨텍스트\n");
        contextBuilder.append("=".repeat(50)).append("\n\n");

        contextBuilder.append("분석 기본 정보:\n");
        contextBuilder.append("- 분석 범위: ").append(context.getAuditScope()).append("\n");
        contextBuilder.append("- 분석 유형: ").append(context.getAnalysisType()).append("\n");
        contextBuilder.append("- 분석 시간: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n\n");

        contextBuilder.append("시스템 현황:\n");
        contextBuilder.append("- 총 사용자 수: ").append(userAnalysis.getTotalUsers()).append("\n");
        contextBuilder.append("- 총 역할 수: ").append(roleAnalysis.getTotalRoles()).append("\n");
        contextBuilder.append("- 총 그룹 수: ").append(groupAnalysis.getTotalGroups()).append("\n");
        contextBuilder.append("- 총 권한 수: ").append(matrix.getPermissionMatrix().size()).append("\n\n");

        contextBuilder.append("이상 징후 요약:\n");
        contextBuilder.append("- 미사용 권한: ").append(anomalyResult.getDormantPermissions()).append("건\n");
        contextBuilder.append("- 과도한 권한: ").append(anomalyResult.getExcessivePermissions()).append("건\n");
        contextBuilder.append("- 미사용 역할: ").append(anomalyResult.getUnusedRoles()).append("건\n");
        contextBuilder.append("- 빈 그룹: ").append(anomalyResult.getEmptyGroups()).append("건\n");
        contextBuilder.append("- 업무 분리 위반: ").append(anomalyResult.getSodViolations()).append("건\n");
        contextBuilder.append("- 총 이상 징후: ").append(anomalyResult.getTotalAnomalies()).append("건\n\n");

        contextBuilder.append("권한 거버넌스 점수:\n");
        contextBuilder.append("- 전체 점수: ").append(String.format("%.1f", governanceScore.getOverallScore())).append("/100점\n");
        contextBuilder.append("- 위험도: ").append(governanceScore.getRiskLevel()).append("\n\n");

        contextBuilder.append("권한 매트릭스 요약:\n");
        contextBuilder.append("- 사용자별 권한 분포: ").append(matrix.getUserMatrix().size()).append("명\n");
        contextBuilder.append("- 역할별 권한 분포: ").append(matrix.getRoleMatrix().size()).append("개\n");
        contextBuilder.append("- 권한별 상세 정보: ").append(matrix.getPermissionMatrix().size()).append("개\n\n");

        contextBuilder.append("💡 권장사항:\n");
        if (anomalyResult.getDormantPermissions() > 0) {
            contextBuilder.append("- 미사용 권한 정리 필요\n");
        }
        if (anomalyResult.getExcessivePermissions() > 0) {
            contextBuilder.append("- 과도한 권한 최소화 필요\n");
        }
        if (anomalyResult.getUnusedRoles() > 0) {
            contextBuilder.append("- 미사용 역할 정리 필요\n");
        }
        if (anomalyResult.getSodViolations() > 0) {
            contextBuilder.append("- 업무 분리 위반 조치 필요\n");
        }

        if (ragDocuments != null && !ragDocuments.isEmpty()) {
            contextBuilder.append("\n관련 거버넌스 문서 (RAG):\n");
            for (int i = 0; i < Math.min(3, ragDocuments.size()); i++) {
                Document doc = ragDocuments.get(i);
                contextBuilder.append("- ").append(doc.getText().substring(0, Math.min(100, doc.getText().length())));
                if (doc.getText().length() > 100) {
                    contextBuilder.append("...");
                }
                contextBuilder.append("\n");
            }
        }
        
        return contextBuilder.toString();
    }

    private static class GovernanceQueryTransformer implements QueryTransformer {
        private final ChatClient chatClient;
        
        public GovernanceQueryTransformer(ChatClient.Builder chatClientBuilder) {
            this.chatClient = chatClientBuilder.build();
        }
        
        @Override
        public Query transform(Query originalQuery) {
            if (originalQuery == null || originalQuery.text() == null) {
                return originalQuery;
            }
            
            String prompt = String.format("""
                권한 거버넌스 분석을 위한 검색 쿼리를 최적화하세요:
                
                원본 쿼리: %s
                
                최적화 지침:
                1. 컴플라이언스 및 규제 관련 용어를 포함하세요
                2. SOD(업무 분리), RBAC 같은 거버넌스 패턴을 추가하세요
                3. 위험 지표와 이상 탐지 관련 키워드를 포함하세요
                4. 감사 및 모니터링 관련 용어를 추가하세요
                
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
            권한 거버넌스 분석 컨텍스트
            ================================
            
            분석 기본 정보:
            - 분석 범위: ALL_USERS
            - 분석 유형: COMPREHENSIVE
            - 분석 시간: %s
            
            시스템 현황:
            - 총 사용자 수: 0
            - 총 역할 수: 0
            - 총 그룹 수: 0
            - 총 권한 수: 0
            
            이상 징후 요약:
            - 미사용 권한: 0건
            - 과도한 권한: 0건
            - 미사용 역할: 0건
            - 빈 그룹: 0건
            - 업무 분리 위반: 0건
            - 총 이상 징후: 0건
            
            권한 거버넌스 점수:
            - 전체 점수: 100.0/100점
            - 위험도: LOW
            
            💡 권장사항:
            - 데이터 수집 실패로 인한 기본 컨텍스트 사용
            """.formatted(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
    }

    private static class PermissionMatrix {
        private final Map<String, Map<String, Object>> userMatrix = new HashMap<>();
        private final Map<String, Map<String, Object>> roleMatrix = new HashMap<>();
        private final Map<String, Map<String, Object>> permissionMatrix = new HashMap<>();

        public Map<String, Map<String, Object>> getUserMatrix() { return userMatrix; }
        public Map<String, Map<String, Object>> getRoleMatrix() { return roleMatrix; }
        public Map<String, Map<String, Object>> getPermissionMatrix() { return permissionMatrix; }
    }

    private static class UserPermissionAnalysis {
        private int totalUsers;
        private final Map<String, Integer> userPermissionCounts = new HashMap<>();
        private final Map<String, Integer> userRoleCounts = new HashMap<>();
        private final Set<String> excessivePermissionUsers = new HashSet<>();
        private final Set<String> dormantUsers = new HashSet<>();

        public int getTotalUsers() { return totalUsers; }
        public void setTotalUsers(int totalUsers) { this.totalUsers = totalUsers; }
        public Map<String, Integer> getUserPermissionCounts() { return userPermissionCounts; }
        public Map<String, Integer> getUserRoleCounts() { return userRoleCounts; }
        public Set<String> getExcessivePermissionUsers() { return excessivePermissionUsers; }
        public Set<String> getDormantUsers() { return dormantUsers; }
    }

    private static class RolePermissionAnalysis {
        private int totalRoles;
        private final Map<String, Integer> rolePermissionCounts = new HashMap<>();
        private final Map<String, Integer> roleUserCounts = new HashMap<>();
        private final Set<String> unusedRoles = new HashSet<>();
        private final Set<String> excessivePermissionRoles = new HashSet<>();

        public int getTotalRoles() { return totalRoles; }
        public void setTotalRoles(int totalRoles) { this.totalRoles = totalRoles; }
        public Map<String, Integer> getRolePermissionCounts() { return rolePermissionCounts; }
        public Map<String, Integer> getRoleUserCounts() { return roleUserCounts; }
        public Set<String> getUnusedRoles() { return unusedRoles; }
        public Set<String> getExcessivePermissionRoles() { return excessivePermissionRoles; }
    }

    private static class GroupPermissionAnalysis {
        private int totalGroups;
        private final Map<String, Integer> groupUserCounts = new HashMap<>();
        private final Set<String> emptyGroups = new HashSet<>();

        public int getTotalGroups() { return totalGroups; }
        public void setTotalGroups(int totalGroups) { this.totalGroups = totalGroups; }
        public Map<String, Integer> getGroupUserCounts() { return groupUserCounts; }
        public Set<String> getEmptyGroups() { return emptyGroups; }
    }

    private static class AnomalyDetectionResult {
        private int dormantPermissions;
        private int excessivePermissions;
        private int unusedRoles;
        private int emptyGroups;
        private int sodViolations;
        private int totalAnomalies;

        public int getDormantPermissions() { return dormantPermissions; }
        public void setDormantPermissions(int dormantPermissions) { this.dormantPermissions = dormantPermissions; }
        public int getExcessivePermissions() { return excessivePermissions; }
        public void setExcessivePermissions(int excessivePermissions) { this.excessivePermissions = excessivePermissions; }
        public int getUnusedRoles() { return unusedRoles; }
        public void setUnusedRoles(int unusedRoles) { this.unusedRoles = unusedRoles; }
        public int getEmptyGroups() { return emptyGroups; }
        public void setEmptyGroups(int emptyGroups) { this.emptyGroups = emptyGroups; }
        public int getSodViolations() { return sodViolations; }
        public void setSodViolations(int sodViolations) { this.sodViolations = sodViolations; }
        public int getTotalAnomalies() { return totalAnomalies; }
        public void setTotalAnomalies(int totalAnomalies) { this.totalAnomalies = totalAnomalies; }
    }

    private static class GovernanceScore {
        private double overallScore;
        private String riskLevel;

        public double getOverallScore() { return overallScore; }
        public void setOverallScore(double overallScore) { this.overallScore = overallScore; }
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    }
} 