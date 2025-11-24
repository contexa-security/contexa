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

/**
 * 권한 거버넌스 분석 컨텍스트 검색기
 *
 * Spring AI RAG 기반 권한 거버넌스 분석
 * 시스템 전체 권한 분포와 사용 현황을 분석하여 잠재적 이상 징후를 탐지
 * 예방적 보안을 구현하여 위협이 발생하기 전에 시스템이 가진 잠재적 위험 요소를 AI가 미리 찾아내어 보고
 * 
 * 분석 대상:
 * - 전체 사용자 권한 매트릭스
 * - 역할별 권한 분포
 * - 리소스별 접근 권한
 * - 미사용 권한 탐지
 * - 과도한 권한 탐지
 * - 업무 분리 위반 검사
 */
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

    // 권한 거버넌스 분석 상수
    private static final int MAX_FINDINGS = 50;
    private static final double DORMANT_PERMISSION_THRESHOLD = 30; // 30일 이상 미사용
    private static final double EXCESSIVE_PERMISSION_THRESHOLD = 20; // 20개 이상 권한
    private static final double SOD_VIOLATION_THRESHOLD = 0.8; // 80% 이상 중복 권한

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

    /**
     * Spring ApplicationContext가 완전히 초기화된 후 호출됩니다.
     * ServletContext, JPA EntityManager, BeanPostProcessor 등이 모두 준비된 상태에서 실행됩니다.
     *
     * @param event ContextRefreshedEvent
     */
    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        log.info("ApplicationContext refreshed. Initializing AccessGovernanceContextRetriever...");
        registerSelf();
    }

    private void registerSelf() {
        // RAG Advisor 생성 (사용 가능한 경우)
        if (chatClientBuilder != null && vectorStore != null) {
            createGovernanceAdvisor();
        }

        registry.registerRetriever(AccessGovernanceContext.class, this);
        log.info("AccessGovernanceContextRetriever 자동 등록 완료 (Spring AI RAG 지원)");
    }
    
    /**
     * 거버넌스 전용 RAG Advisor 생성
     */
    private void createGovernanceAdvisor() {
        // 거버넌스 쿼리 변환기
        QueryTransformer governanceQueryTransformer = new GovernanceQueryTransformer(chatClientBuilder);
        
        // 거버넌스 필터 구성
        FilterExpressionBuilder filterBuilder = new FilterExpressionBuilder();
        var filter = filterBuilder.and(
            filterBuilder.in("documentType", "governance", "policy", "compliance", "audit"),
            filterBuilder.gte("relevanceScore", 0.7)
        ).build();
        
        // VectorStoreDocumentRetriever 구성
        VectorStoreDocumentRetriever retriever = VectorStoreDocumentRetriever.builder()
            .vectorStore(vectorStore)
            .similarityThreshold(governanceSimilarityThreshold)
            .topK(governanceTopK)
            .filterExpression(filter)
            .build();
        
        // Governance RAG Advisor 생성
        governanceAdvisor = RetrievalAugmentationAdvisor.builder()
            .documentRetriever(retriever)
            .queryTransformers(governanceQueryTransformer)
            .build();
        
        // 부모 클래스에 Advisor 등록
        registerDomainAdvisor(AccessGovernanceContext.class, governanceAdvisor);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof AccessGovernanceContext) {
            // RAG 기반 검색 시도
            ContextRetrievalResult ragResult = null;
            if (governanceAdvisor != null) {
                ragResult = super.retrieveContext(request);
            }
            
            // 기존 거버넌스 분석 수행
            String contextInfo = retrieveAccessGovernanceContext(
                (AIRequest<AccessGovernanceContext>) request,
                ragResult != null ? ragResult.getDocuments() : List.of()
            );
            
            // 메타데이터 병합
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

    /**
     * 권한 거버넌스 분석 컨텍스트 검색
     */
    public String retrieveAccessGovernanceContext(AIRequest<AccessGovernanceContext> request, List<Document> ragDocuments) {
        log.info("권한 거버넌스 분석 시작: scope={}, type={}", 
                request.getContext().getAuditScope(), 
                request.getContext().getAnalysisType());

        try {
            AccessGovernanceContext context = request.getContext();
            
            // VectorService에 거버넌스 컨텍스트 저장
            try {
                vectorService.storeGovernanceContext(context);
            } catch (Exception e) {
                log.error("벡터 저장소 컨텍스트 저장 실패", e);
            }

            // 1. 전체 권한 매트릭스 수집
            PermissionMatrix permissionMatrix = collectPermissionMatrix(context);

            // 2. 사용자별 권한 분석
            UserPermissionAnalysis userAnalysis = analyzeUserPermissions(context, permissionMatrix);

            // 3. 역할별 권한 분석
            RolePermissionAnalysis roleAnalysis = analyzeRolePermissions(context, permissionMatrix);

            // 4. 그룹별 권한 분석
            GroupPermissionAnalysis groupAnalysis = analyzeGroupPermissions(context, permissionMatrix);

            // 5. 이상 징후 탐지
            AnomalyDetectionResult anomalyResult = detectAnomalies(context, permissionMatrix, userAnalysis, roleAnalysis, groupAnalysis);

            // 6. 권한 거버넌스 점수 계산
            GovernanceScore governanceScore = calculateGovernanceScore(anomalyResult);
            
            // 7. VectorService를 통한 유사 거버넌스 문서 검색
            List<Document> vectorServiceDocs = List.of();
            try {
                String query = String.format("거버넌스 분석: scope=%s, type=%s, 이상 징후=%d", 
                    context.getAuditScope(), context.getAnalysisType(), anomalyResult.getTotalAnomalies());
                vectorServiceDocs = vectorService.findSimilarGovernanceDocuments(query, 10);
                log.debug("벡터 서비스에서 {} 개의 유사 거버넌스 문서 검색", vectorServiceDocs.size());
            } catch (Exception e) {
                log.error("벡터 서비스 검색 실패", e);
            }
            
            // RAG 문서와 VectorService 문서 병합
            List<Document> allDocuments = new ArrayList<>();
            if (ragDocuments != null) {
                allDocuments.addAll(ragDocuments);
            }
            allDocuments.addAll(vectorServiceDocs);

            // 8. 종합 컨텍스트 생성
            String comprehensiveContext = buildComprehensiveContext(
                    context, permissionMatrix, userAnalysis, roleAnalysis, groupAnalysis, 
                    anomalyResult, governanceScore, allDocuments);

            log.info("권한 거버넌스 분석 완료: {} 사용자, {} 역할, {} 이상 징후 발견", 
                    userAnalysis.getTotalUsers(), 
                    roleAnalysis.getTotalRoles(), 
                    anomalyResult.getTotalAnomalies());

            return comprehensiveContext;

        } catch (Exception e) {
            log.error("권한 거버넌스 분석 실패", e);
            return getDefaultContext();
        }
    }

    /**
     * 전체 권한 매트릭스 수집
     */
    private PermissionMatrix collectPermissionMatrix(AccessGovernanceContext context) {
        log.debug("권한 매트릭스 수집 시작");

        PermissionMatrix matrix = new PermissionMatrix();

        // 사용자별 권한 매트릭스
        List<Users> users = userRepository.findAll();
        for (Users user : users) {
            Map<String, Object> userPermissions = new HashMap<>();
            userPermissions.put("userId", user.getId());
            userPermissions.put("username", user.getUsername());
            userPermissions.put("roles", user.getRoleNames());
            userPermissions.put("permissions", user.getPermissionNames());
            userPermissions.put("groups", user.getUserGroups().stream().map(ug -> ug.getGroup().getName()).collect(Collectors.toList()));
            userPermissions.put("lastLoginTime", user.getLastMfaUsedAt()); // MFA 사용 시간을 마지막 로그인으로 사용
            userPermissions.put("enabled", true); // 기본값으로 설정
            
            matrix.getUserMatrix().put(user.getId().toString(), userPermissions);
        }

        // 역할별 권한 매트릭스
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

        // 권한별 상세 정보
        List<Permission> permissions = permissionRepository.findAll();
        for (Permission permission : permissions) {
            Map<String, Object> permissionDetails = new HashMap<>();
            permissionDetails.put("permissionId", permission.getId());
            permissionDetails.put("permissionName", permission.getName());
            permissionDetails.put("friendlyName", permission.getFriendlyName());
            permissionDetails.put("description", permission.getDescription());
            permissionDetails.put("targetType", permission.getTargetType());
            permissionDetails.put("actionType", permission.getActionType());
            // RolePermission을 통해 역방향으로 권한-역할 관계 조회
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

        log.debug("권한 매트릭스 수집 완료: {} 사용자, {} 역할, {} 권한", 
                matrix.getUserMatrix().size(), 
                matrix.getRoleMatrix().size(), 
                matrix.getPermissionMatrix().size());

        return matrix;
    }

    /**
     * 사용자별 권한 분석
     */
    private UserPermissionAnalysis analyzeUserPermissions(AccessGovernanceContext context, PermissionMatrix matrix) {
        log.debug("👥 사용자별 권한 분석 시작");

        UserPermissionAnalysis analysis = new UserPermissionAnalysis();
        analysis.setTotalUsers(matrix.getUserMatrix().size());

        for (Map.Entry<String, Map<String, Object>> entry : matrix.getUserMatrix().entrySet()) {
            String userId = entry.getKey();
            Map<String, Object> userData = entry.getValue();
            
            List<String> permissions = (List<String>) userData.get("permissions");
            List<String> roles = (List<String>) userData.get("roles");
            
            // 권한 개수 분석
            int permissionCount = permissions != null ? permissions.size() : 0;
            int roleCount = roles != null ? roles.size() : 0;
            
            analysis.getUserPermissionCounts().put(userId, permissionCount);
            analysis.getUserRoleCounts().put(userId, roleCount);
            
            // 과도한 권한 탐지
            if (permissionCount > EXCESSIVE_PERMISSION_THRESHOLD) {
                analysis.getExcessivePermissionUsers().add(userId);
            }
            
            // 미사용 사용자 탐지 (마지막 로그인 시간 기준)
            LocalDateTime lastLoginTime = (LocalDateTime) userData.get("lastLoginTime");
            if (lastLoginTime != null && lastLoginTime.isBefore(LocalDateTime.now().minusDays((long) DORMANT_PERMISSION_THRESHOLD))) {
                analysis.getDormantUsers().add(userId);
            }
        }

        log.debug("👥 사용자별 권한 분석 완료: {} 과도한 권한 사용자, {} 미사용 사용자", 
                analysis.getExcessivePermissionUsers().size(), 
                analysis.getDormantUsers().size());

        return analysis;
    }

    /**
     * 역할별 권한 분석
     */
    private RolePermissionAnalysis analyzeRolePermissions(AccessGovernanceContext context, PermissionMatrix matrix) {
        log.debug("역할별 권한 분석 시작");

        RolePermissionAnalysis analysis = new RolePermissionAnalysis();
        analysis.setTotalRoles(matrix.getRoleMatrix().size());

        for (Map.Entry<String, Map<String, Object>> entry : matrix.getRoleMatrix().entrySet()) {
            String roleId = entry.getKey();
            Map<String, Object> roleData = entry.getValue();
            
            @SuppressWarnings("unchecked")
            List<String> permissions = (List<String>) roleData.get("permissions");
            @SuppressWarnings("unchecked")
            List<String> users = (List<String>) roleData.get("users");
            
            // 권한 개수 분석
            int permissionCount = permissions != null ? permissions.size() : 0;
            int userCount = users != null ? users.size() : 0;
            
            analysis.getRolePermissionCounts().put(roleId, permissionCount);
            analysis.getRoleUserCounts().put(roleId, userCount);
            
            // 미사용 역할 탐지
            if (userCount == 0) {
                analysis.getUnusedRoles().add(roleId);
            }
            
            // 과도한 권한 역할 탐지
            if (permissionCount > EXCESSIVE_PERMISSION_THRESHOLD) {
                analysis.getExcessivePermissionRoles().add(roleId);
            }
        }

        log.debug("역할별 권한 분석 완료: {} 미사용 역할, {} 과도한 권한 역할", 
                analysis.getUnusedRoles().size(), 
                analysis.getExcessivePermissionRoles().size());

        return analysis;
    }

    /**
     * 그룹별 권한 분석
     */
    private GroupPermissionAnalysis analyzeGroupPermissions(AccessGovernanceContext context, PermissionMatrix matrix) {
        log.debug("👥 그룹별 권한 분석 시작");

        GroupPermissionAnalysis analysis = new GroupPermissionAnalysis();
        
        // 그룹 정보 수집 (실제 구현에서는 Group 엔티티에서 권한 정보를 가져와야 함)
        List<Group> groups = groupRepository.findAll();
        analysis.setTotalGroups(groups.size());

        for (Group group : groups) {
            // 그룹별 사용자 수
            int userCount = group.getUserGroups().size();
            analysis.getGroupUserCounts().put(group.getId().toString(), userCount);
            
            // 빈 그룹 탐지
            if (userCount == 0) {
                analysis.getEmptyGroups().add(group.getId().toString());
            }
        }

        log.debug("👥 그룹별 권한 분석 완료: {} 그룹, {} 빈 그룹", 
                analysis.getTotalGroups(), 
                analysis.getEmptyGroups().size());

        return analysis;
    }

    /**
     * 이상 징후 탐지
     */
    private AnomalyDetectionResult detectAnomalies(AccessGovernanceContext context, PermissionMatrix matrix,
                                                  UserPermissionAnalysis userAnalysis, 
                                                  RolePermissionAnalysis roleAnalysis,
                                                  GroupPermissionAnalysis groupAnalysis) {
        log.debug("이상 징후 탐지 시작");

        AnomalyDetectionResult result = new AnomalyDetectionResult();

        // 1. 미사용 권한 탐지
        result.setDormantPermissions(userAnalysis.getDormantUsers().size());

        // 2. 과도한 권한 탐지
        result.setExcessivePermissions(userAnalysis.getExcessivePermissionUsers().size() + 
                                     roleAnalysis.getExcessivePermissionRoles().size());

        // 3. 미사용 역할 탐지
        result.setUnusedRoles(roleAnalysis.getUnusedRoles().size());

        // 4. 빈 그룹 탐지
        result.setEmptyGroups(groupAnalysis.getEmptyGroups().size());

        // 5. 업무 분리 위반 탐지 (간단한 구현)
        result.setSodViolations(detectSodViolations(matrix));

        result.setTotalAnomalies(result.getDormantPermissions() + result.getExcessivePermissions() + 
                               result.getUnusedRoles() + result.getEmptyGroups() + result.getSodViolations());

        log.debug("이상 징후 탐지 완료: {} 총 이상 징후", result.getTotalAnomalies());

        return result;
    }

    /**
     * 업무 분리 위반 탐지 (간단한 구현)
     */
    private int detectSodViolations(PermissionMatrix matrix) {
        // 실제 구현에서는 더 복잡한 업무 분리 규칙을 적용해야 함
        // 여기서는 간단히 높은 권한을 가진 사용자 수를 반환
        int highPrivilegeUsers = 0;
        
        for (Map<String, Object> userData : matrix.getUserMatrix().values()) {
            @SuppressWarnings("unchecked")
            List<String> permissions = (List<String>) userData.get("permissions");
            if (permissions != null && permissions.size() > 15) { // 15개 이상 권한을 높은 권한으로 간주
                highPrivilegeUsers++;
            }
        }
        
        return highPrivilegeUsers;
    }

    /**
     * 권한 거버넌스 점수 계산
     */
    private GovernanceScore calculateGovernanceScore(AnomalyDetectionResult anomalyResult) {
        log.debug("권한 거버넌스 점수 계산 시작");

        GovernanceScore score = new GovernanceScore();

        // 기본 점수 100점에서 이상 징후에 따라 감점
        double baseScore = 100.0;
        
        // 각 이상 징후별 가중치
        double deduction = anomalyResult.getDormantPermissions() * 2.0 +
                          anomalyResult.getExcessivePermissions() * 3.0 +
                          anomalyResult.getUnusedRoles() * 1.5 +
                          anomalyResult.getEmptyGroups() * 1.0 +
                          anomalyResult.getSodViolations() * 5.0;

        score.setOverallScore(Math.max(0, baseScore - deduction));
        
        // 위험도 결정
        if (score.getOverallScore() >= 80) {
            score.setRiskLevel("LOW");
        } else if (score.getOverallScore() >= 60) {
            score.setRiskLevel("MEDIUM");
        } else if (score.getOverallScore() >= 40) {
            score.setRiskLevel("HIGH");
        } else {
            score.setRiskLevel("CRITICAL");
        }

        log.debug("권한 거버넌스 점수 계산 완료: {}점, 위험도: {}", 
                score.getOverallScore(), score.getRiskLevel());

        return score;
    }

    /**
     * 종합 컨텍스트 생성
     */
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
        
        // 기본 정보
        contextBuilder.append("분석 기본 정보:\n");
        contextBuilder.append("- 분석 범위: ").append(context.getAuditScope()).append("\n");
        contextBuilder.append("- 분석 유형: ").append(context.getAnalysisType()).append("\n");
        contextBuilder.append("- 분석 시간: ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n\n");
        
        // 시스템 현황
        contextBuilder.append("시스템 현황:\n");
        contextBuilder.append("- 총 사용자 수: ").append(userAnalysis.getTotalUsers()).append("\n");
        contextBuilder.append("- 총 역할 수: ").append(roleAnalysis.getTotalRoles()).append("\n");
        contextBuilder.append("- 총 그룹 수: ").append(groupAnalysis.getTotalGroups()).append("\n");
        contextBuilder.append("- 총 권한 수: ").append(matrix.getPermissionMatrix().size()).append("\n\n");
        
        // 이상 징후 요약
        contextBuilder.append("이상 징후 요약:\n");
        contextBuilder.append("- 미사용 권한: ").append(anomalyResult.getDormantPermissions()).append("건\n");
        contextBuilder.append("- 과도한 권한: ").append(anomalyResult.getExcessivePermissions()).append("건\n");
        contextBuilder.append("- 미사용 역할: ").append(anomalyResult.getUnusedRoles()).append("건\n");
        contextBuilder.append("- 빈 그룹: ").append(anomalyResult.getEmptyGroups()).append("건\n");
        contextBuilder.append("- 업무 분리 위반: ").append(anomalyResult.getSodViolations()).append("건\n");
        contextBuilder.append("- 총 이상 징후: ").append(anomalyResult.getTotalAnomalies()).append("건\n\n");
        
        // 권한 거버넌스 점수
        contextBuilder.append("권한 거버넌스 점수:\n");
        contextBuilder.append("- 전체 점수: ").append(String.format("%.1f", governanceScore.getOverallScore())).append("/100점\n");
        contextBuilder.append("- 위험도: ").append(governanceScore.getRiskLevel()).append("\n\n");
        
        // 상세 권한 매트릭스 (요약)
        contextBuilder.append("권한 매트릭스 요약:\n");
        contextBuilder.append("- 사용자별 권한 분포: ").append(matrix.getUserMatrix().size()).append("명\n");
        contextBuilder.append("- 역할별 권한 분포: ").append(matrix.getRoleMatrix().size()).append("개\n");
        contextBuilder.append("- 권한별 상세 정보: ").append(matrix.getPermissionMatrix().size()).append("개\n\n");
        
        // 권장사항
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
        
        // RAG 검색 결과 추가 (있는 경우)
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
    
    /**
     * 거버넌스 쿼리 변환기
     */
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

    /**
     * 기본 컨텍스트 반환
     */
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

    // 내부 클래스들
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