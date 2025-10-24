package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.strategy.IAuthorizationAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * IDOR (Insecure Direct Object Reference) 공격 전략 구현
 */
public class IDORStrategy extends BaseAttackStrategy implements IAuthorizationAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }
    private static final Logger logger = LoggerFactory.getLogger(IDORStrategy.class);
    
    public IDORStrategy() {
        // 기본 생성자
    }

    private String generateRandomIp() {
        Random random = ThreadLocalRandom.current();
        return String.format("%d.%d.%d.%d",
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256));
    }
    
    // IDOR 공격 벡터들
    private enum IdorVector {
        SEQUENTIAL_ID("Sequential ID Enumeration"),
        UUID_PREDICTION("UUID Prediction"),
        PARAMETER_TAMPERING("Parameter Tampering"),
        PATH_TRAVERSAL("Path Traversal"),
        REFERENCE_MANIPULATION("Reference Manipulation"),
        HIDDEN_FIELD_MANIPULATION("Hidden Field Manipulation"),
        COOKIE_MANIPULATION("Cookie Manipulation"),
        JWT_CLAIM_MANIPULATION("JWT Claim Manipulation"),
        API_PARAMETER_POLLUTION("API Parameter Pollution"),
        GRAPHQL_FIELD_INJECTION("GraphQL Field Injection");
        
        private final String description;
        
        IdorVector(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    // 타겟 리소스 타입
    private enum ResourceType {
        USER_PROFILE("User Profile"),
        DOCUMENT("Document"),
        INVOICE("Invoice"),
        ORDER("Order"),
        PAYMENT("Payment Information"),
        MEDICAL_RECORD("Medical Record"),
        ADMIN_PANEL("Admin Panel"),
        API_KEY("API Key"),
        CONFIGURATION("Configuration"),
        REPORT("Report");
        
        private final String name;
        
        ResourceType(String name) {
            this.name = name;
        }
        
        public String getName() {
            return name;
        }
    }
    
    public AttackResult execute(String targetUser, Map<String, Object> parameters) {
        LocalDateTime startTime = LocalDateTime.now();

        // 공격 벡터 선택
        IdorVector vector = selectAttackVector(parameters);
        ResourceType resourceType = selectResourceType(parameters);

        // 공격 소스 IP 생성
        String sourceIp = generateRandomIp();

        logger.info("Executing IDOR attack using {} on {} from {}",
                   vector.getDescription(), resourceType.getName(), sourceIp);

        // 공격 결과 생성
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.IDOR)
            .attackName("IDOR - " + vector.name())
            .executionTime(startTime)
            .timestamp(startTime)
            .targetUser(targetUser)
            .targetResource(resourceType.getName())
            .description(vector.getDescription())
            .mitreTechnique("T1548.002")
            .sourceIp(sourceIp)
            .attackDetails(Map.of(
                "vector", vector.name(),
                "resource_type", resourceType.name(),
                "attack_technique", vector.getDescription()
            ))
            .build();

        // 공격 시뮬레이션
        boolean attackSuccess = simulateIdorAttack(vector, resourceType, result);

        // IDOR 공격 성공 시 @Protectable로 보호된 고객 데이터 접근 시도
        if (attackSuccess) {
            // 공격 컨텍스트 생성
            AttackContext attackContext = new AttackContext();
            attackContext.setAttackId(result.getAttackId());
            attackContext.setCampaignId(result.getCampaignId());
            attackContext.setTargetUser(targetUser);
            attackContext.setSourceIp(sourceIp);
            attackContext.setUserAgent("IDOR-Attack-Agent");

            // 타겟 고객 ID 생성 (IDOR 특성상 다른 사용자의 데이터 접근)
            String targetCustomerId = "customer-" + ThreadLocalRandom.current().nextInt(1000, 2000);
            boolean dataBreached = attemptCustomerDataAccess(
                targetCustomerId,
                "IDOR",
                attackContext
            );

            result.setDataBreached(dataBreached);
            result.setBreachedRecordCount(dataBreached ? 1 : 0);
        }

        result.setAttackSuccessful(attackSuccess);
        result.setSuccessful(attackSuccess);

        // 이벤트 발행 - Authorization Decision Event 사용
        if (eventPublisher != null) {
            String resource = String.format("%s:%s", resourceType.getName(), result.getTargetResource());
            String action = String.format("IDOR_%s", vector.name());

            eventPublisher.publishAuthorizationDecision(
                result,
                targetUser,
                resource,
                action,
                attackSuccess, // granted 여부
                attackSuccess ?
                    String.format("IDOR attack succeeded using %s", vector.getDescription()) :
                    String.format("IDOR attack blocked - %s", vector.getDescription())
            );
        }

        // 탐지 시뮬레이션
        simulateDetection(result, vector);

        // 위험도 평가
        evaluateRisk(result, vector, resourceType, attackSuccess);

        // 증거 수집
        collectEvidence(result, vector, resourceType);

        // 메트릭 계산
        calculateMetrics(result, startTime);

        return result;
    }
    
    private IdorVector selectAttackVector(Map<String, Object> parameters) {
        String vector = (String) parameters.get("vector");
        if (vector != null) {
            try {
                return IdorVector.valueOf(vector);
            } catch (IllegalArgumentException e) {
                // 잘못된 벡터명인 경우 랜덤 선택
            }
        }
        
        // 랜덤 선택
        IdorVector[] vectors = IdorVector.values();
        return vectors[ThreadLocalRandom.current().nextInt(vectors.length)];
    }
    
    private ResourceType selectResourceType(Map<String, Object> parameters) {
        String type = (String) parameters.get("resourceType");
        if (type != null) {
            try {
                return ResourceType.valueOf(type);
            } catch (IllegalArgumentException e) {
                // 잘못된 타입명인 경우 랜덤 선택
            }
        }
        
        // 랜덤 선택
        ResourceType[] types = ResourceType.values();
        return types[ThreadLocalRandom.current().nextInt(types.length)];
    }
    
    private boolean simulateIdorAttack(IdorVector vector, ResourceType resourceType, AttackResult result) {
        Random random = ThreadLocalRandom.current();
        Map<String, Object> attackPayload = new HashMap<>();
        
        // 공격 벡터별 시뮬레이션
        switch (vector) {
            case SEQUENTIAL_ID:
                int originalId = random.nextInt(1000, 2000);
                int targetId = originalId + random.nextInt(1, 100);
                attackPayload.put("original_id", originalId);
                attackPayload.put("target_id", targetId);
                attackPayload.put("method", "ID increment/decrement");
                result.setAttackVector("sequential_id");
                return random.nextDouble() < 0.6; // 60% 성공률
                
            case UUID_PREDICTION:
                attackPayload.put("original_uuid", UUID.randomUUID().toString());
                attackPayload.put("predicted_uuid", UUID.randomUUID().toString());
                attackPayload.put("prediction_method", "Pattern analysis");
                result.setAttackVector("uuid_prediction");
                return random.nextDouble() < 0.15; // 15% 성공률 (UUID는 예측이 어려움)
                
            case PARAMETER_TAMPERING:
                attackPayload.put("parameter", "userId");
                attackPayload.put("original_value", "user123");
                attackPayload.put("tampered_value", "admin456");
                result.setAttackVector("parameter_tampering");
                return random.nextDouble() < 0.45; // 45% 성공률
                
            case PATH_TRAVERSAL:
                attackPayload.put("original_path", "/api/users/profile");
                attackPayload.put("traversal_path", "/api/users/../admin/profile");
                result.setAttackVector("path_traversal");
                return random.nextDouble() < 0.35; // 35% 성공률
                
            case REFERENCE_MANIPULATION:
                attackPayload.put("reference_field", "documentRef");
                attackPayload.put("original_ref", "DOC-2024-001");
                attackPayload.put("manipulated_ref", "DOC-2024-999");
                result.setAttackVector("reference_manipulation");
                return random.nextDouble() < 0.5; // 50% 성공률
                
            case HIDDEN_FIELD_MANIPULATION:
                attackPayload.put("field_name", "hidden_user_id");
                attackPayload.put("original_value", "12345");
                attackPayload.put("manipulated_value", "99999");
                result.setAttackVector("hidden_field");
                return random.nextDouble() < 0.4; // 40% 성공률
                
            case COOKIE_MANIPULATION:
                attackPayload.put("cookie_name", "user_session");
                attackPayload.put("original_value", "sess_user_12345");
                attackPayload.put("manipulated_value", "sess_admin_99999");
                result.setAttackVector("cookie");
                return random.nextDouble() < 0.3; // 30% 성공률
                
            case JWT_CLAIM_MANIPULATION:
                attackPayload.put("claim", "sub");
                attackPayload.put("original_value", "user:12345");
                attackPayload.put("manipulated_value", "user:99999");
                result.setAttackVector("jwt");
                return random.nextDouble() < 0.25; // 25% 성공률
                
            case API_PARAMETER_POLLUTION:
                attackPayload.put("endpoint", "/api/data");
                attackPayload.put("parameters", Arrays.asList("id=123", "id=456", "id=789"));
                result.setAttackVector("parameter_pollution");
                return random.nextDouble() < 0.35; // 35% 성공률
                
            case GRAPHQL_FIELD_INJECTION:
                attackPayload.put("query", "{ user(id: 123) { ... on Admin { secretData } } }");
                result.setAttackVector("graphql");
                return random.nextDouble() < 0.3; // 30% 성공률
                
            default:
                return false;
        }
    }
    
    private void simulateDetection(AttackResult result, IdorVector vector) {
        Random random = ThreadLocalRandom.current();
        
        // 벡터별 탐지 확률
        double detectionProbability;
        switch (vector) {
            case SEQUENTIAL_ID:
                detectionProbability = 0.7; // 순차적 ID 접근은 탐지가 쉬움
                break;
            case UUID_PREDICTION:
                detectionProbability = 0.3; // UUID 예측 시도는 탐지가 어려움
                break;
            case PATH_TRAVERSAL:
                detectionProbability = 0.8; // 경로 탐색은 쉽게 탐지됨
                break;
            case JWT_CLAIM_MANIPULATION:
                detectionProbability = 0.75; // JWT 조작은 서명 검증으로 탐지
                break;
            case COOKIE_MANIPULATION:
                detectionProbability = 0.65; // 쿠키 조작은 중간 정도
                break;
            default:
                detectionProbability = 0.5;
        }
        
        boolean detected = random.nextDouble() < detectionProbability;
        result.setDetected(detected);
        
        if (detected) {
            result.setDetectionTime(LocalDateTime.now());
            result.setDetectionTimeMs((long)(random.nextDouble() * 3000 + 500)); // 0.5-3.5초
            
            // 탐지 방법
            if (random.nextDouble() < 0.5) {
                result.setDetectionMethod("access_pattern_analysis");
                result.getTriggeredPolicies().add("IDOR_PREVENTION_POLICY");
            } else {
                result.setDetectionMethod("ai_behavioral_analysis");
                result.setAiConfidenceScore(0.6 + random.nextDouble() * 0.4);
            }
            
            // 차단 여부
            result.setBlocked(random.nextDouble() < 0.7);
        }
    }
    
    private void evaluateRisk(AttackResult result, IdorVector vector, ResourceType resourceType, boolean success) {
        double riskScore;
        
        if (success) {
            // 리소스 타입에 따른 위험도
            switch (resourceType) {
                case MEDICAL_RECORD:
                case PAYMENT:
                case ADMIN_PANEL:
                case API_KEY:
                    riskScore = 0.95; // 매우 민감한 데이터
                    break;
                case USER_PROFILE:
                case INVOICE:
                case ORDER:
                    riskScore = 0.8; // 민감한 데이터
                    break;
                case DOCUMENT:
                case REPORT:
                    riskScore = 0.7; // 중요 데이터
                    break;
                default:
                    riskScore = 0.6;
            }
        } else {
            // 실패한 공격도 위험도 부여
            riskScore = 0.3 + ThreadLocalRandom.current().nextDouble() * 0.2;
        }
        
        result.setRiskScore(riskScore);
        result.setRiskLevel(AttackResult.RiskLevel.fromScore(riskScore).name());
        
        // 영향도 평가
        if (riskScore >= 0.9) {
            result.setImpactAssessment("Critical - Unauthorized access to highly sensitive data");
        } else if (riskScore >= 0.7) {
            result.setImpactAssessment("High - Potential data breach and privacy violation");
        } else if (riskScore >= 0.5) {
            result.setImpactAssessment("Medium - Limited unauthorized data access");
        } else {
            result.setImpactAssessment("Low - Failed IDOR attempt with minimal impact");
        }
    }
    
    private void collectEvidence(AttackResult result, IdorVector vector, ResourceType resourceType) {
        // HTTP 요청 증거
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "IDORBot/1.0");
        headers.put("Referer", "https://example.com/dashboard");
        
        // 벡터별 추가 헤더
        switch (vector) {
            case COOKIE_MANIPULATION:
                headers.put("Cookie", "session=manipulated_value");
                break;
            case JWT_CLAIM_MANIPULATION:
                headers.put("Authorization", "Bearer manipulated_jwt_token");
                break;
            case PATH_TRAVERSAL:
                headers.put("X-Original-Path", "/api/users/profile");
                break;
        }
        
        result.setHttpHeaders(headers);
        
        // 증거 수집
        AttackResult.Evidence evidence = AttackResult.Evidence.builder()
            .type("idor_attempt")
            .timestamp(LocalDateTime.now())
            .source(resourceType.getName())
            .content(String.format("IDOR attack attempt using %s on %s", 
                    vector.getDescription(), resourceType.getName()))
            .metadata(Map.of(
                "vector", vector.name(),
                "resource", resourceType.name(),
                "success", String.valueOf(result.isAttackSuccessful())
            ))
            .build();
        
        result.getEvidences().add(evidence);
        
        // 공격 페이로드 저장
        result.getAttackPayload().put("vector", vector.name());
        result.getAttackPayload().put("target_resource", resourceType.getName());
    }
    
    private void calculateMetrics(AttackResult result, LocalDateTime startTime) {
        long duration = java.time.Duration.between(startTime, LocalDateTime.now()).toMillis();
        result.setDuration(duration);
        result.setResponseTimeMs(duration);
        
        // HTTP 상태 코드 설정
        if (result.isAttackSuccessful()) {
            result.setHttpStatusCode(200); // 성공적으로 접근
        } else if (result.isBlocked()) {
            result.setHttpStatusCode(403); // 접근 거부
        } else {
            result.setHttpStatusCode(404); // 리소스를 찾을 수 없음
        }
        
        // 데이터 유출량 시뮬레이션 (성공한 경우)
        if (result.isAttackSuccessful()) {
            result.setDataExfiltratedBytes(
                ThreadLocalRandom.current().nextLong(1024, 1024 * 1024) // 1KB - 1MB
            );
        }
    }
    
    // IAuthorizationAttack 인터페이스 메서드 구현
    @Override
    public boolean attemptPrivilegeEscalation(String currentRole, String targetRole) {
        return ThreadLocalRandom.current().nextDouble() < 0.3;
    }
    
    @Override
    public IdorResult attemptIdorAttack(String objectId, String targetObjectId) {
        IdorResult result = new IdorResult();
        boolean success = ThreadLocalRandom.current().nextDouble() < 0.45;
        result.setSuccessful(success);
        result.setObjectId(targetObjectId);
        result.setResponseCode(success ? 200 : 403);
        result.setAttacker("idor_attacker");
        result.setUrl("/api/objects/" + targetObjectId);
        result.setAccessedData(success ? "User private data: " + targetObjectId : null);
        result.setDetected(!success);
        result.setDetectionMethod(success ? null : "AI-based anomaly detection");
        result.setDataType("user_data");
        result.setSensitivity(success ? "CRITICAL" : "NONE");
        return result;
    }
    
    @Override
    public boolean attemptApiBypass(String apiEndpoint, ApiBypassTechnique bypassTechnique) {
        // API 우회 시도
        double successRate = switch(bypassTechnique) {
            case HTTP_METHOD_OVERRIDE -> 0.4;
            case PARAMETER_POLLUTION -> 0.35;
            case PATH_TRAVERSAL -> 0.45;
            default -> 0.25;
        };
        return ThreadLocalRandom.current().nextDouble() < successRate;
    }
    
    @Override
    public boolean attemptHorizontalEscalation(String userId, String targetUserId) {
        return ThreadLocalRandom.current().nextDouble() < 0.4;
    }
    
    @Override
    public String manipulateRole(String jwtToken, String newRole) {
        // JWT 토큰 조작
        if (ThreadLocalRandom.current().nextDouble() < 0.25) {
            return jwtToken.replace("role:user", "role:" + newRole);
        }
        return jwtToken;
    }
    
    @Override
    public Map<String, List<String>> analyzePermissionMatrix(String role) {
        Map<String, List<String>> matrix = new HashMap<>();
        
        // 역할별 권한 매트릭스
        switch (role) {
            case "admin":
                matrix.put("read", Arrays.asList("all_users", "all_documents", "all_logs"));
                matrix.put("write", Arrays.asList("all_users", "all_documents", "configurations"));
                matrix.put("delete", Arrays.asList("all_users", "all_documents"));
                matrix.put("execute", Arrays.asList("admin_functions", "system_commands"));
                break;
                
            case "manager":
                matrix.put("read", Arrays.asList("team_users", "team_documents", "team_logs"));
                matrix.put("write", Arrays.asList("team_users", "team_documents"));
                matrix.put("delete", Arrays.asList("team_documents"));
                matrix.put("execute", Arrays.asList("manager_functions"));
                break;
                
            case "user":
                matrix.put("read", Arrays.asList("own_profile", "own_documents", "public_documents"));
                matrix.put("write", Arrays.asList("own_profile", "own_documents"));
                matrix.put("delete", Arrays.asList("own_documents"));
                matrix.put("execute", Arrays.asList("user_functions"));
                break;
                
            default:
                matrix.put("read", Arrays.asList("public_documents"));
                matrix.put("write", new ArrayList<>());
                matrix.put("delete", new ArrayList<>());
                matrix.put("execute", new ArrayList<>());
        }
        
        return matrix;
    }
    
    @Override
    public ResourceAccessResult attemptAccess(String resource, String method) {
        ResourceAccessResult result = new ResourceAccessResult();
        result.setResourceId(resource);
        result.setAccessible(ThreadLocalRandom.current().nextDouble() < 0.45);
        result.setHttpStatusCode(result.isAccessible() ? 200 : 403);
        result.setProtectedByAi(true);
        result.setDenialReason(result.isAccessible() ? null : "IDOR attempt detected and blocked");
        return result;
    }
    
    @Override
    public List<ProtectedResource> scanProtectedResources() {
        List<ProtectedResource> resources = new ArrayList<>();
        
        // IDOR 취약 리소스 스캔
        String[] vulnerablePaths = {
            "/api/users/{id}",
            "/api/documents/{id}",
            "/api/invoices/{id}",
            "/api/orders/{id}",
            "/api/messages/{id}",
            "/api/profiles/{id}"
        };
        
        for (String path : vulnerablePaths) {
            ProtectedResource resource = new ProtectedResource();
            resource.setPath(path);
            resource.setHttpMethod("GET");
            resource.setProtectionLevel(ThreadLocalRandom.current().nextBoolean() ? "HIGH" : "MEDIUM");
            resource.setAiEvaluation(true);
            resource.setRiskLevel("HIGH");
            
            List<String> requiredRoles = new ArrayList<>();
            if (path.contains("invoices") || path.contains("orders")) {
                requiredRoles.add("FINANCE");
                requiredRoles.add("ADMIN");
            } else {
                requiredRoles.add("USER");
            }
            resource.setRequiredRoles(requiredRoles);
            
            resources.add(resource);
        }
        
        return resources;
    }
    
    public List<AttackResult> generateCampaign(String targetOrganization, int numberOfAttacks) {
        List<AttackResult> results = new ArrayList<>();
        
        for (int i = 0; i < numberOfAttacks; i++) {
            // 다양한 IDOR 벡터를 순차적으로 시도
            IdorVector[] vectors = IdorVector.values();
            ResourceType[] resources = ResourceType.values();
            
            IdorVector vector = vectors[i % vectors.length];
            ResourceType resource = resources[i % resources.length];
            
            Map<String, Object> params = new HashMap<>();
            params.put("vector", vector.name());
            params.put("resourceType", resource.name());
            params.put("campaignId", UUID.randomUUID().toString());
            
            String targetUser = String.format("user_%d@%s", i, targetOrganization);
            AttackResult result = execute(targetUser, params);
            result.setCampaignId((String) params.get("campaignId"));
            
            results.add(result);
            
            // 공격 간 지연
            try {
                Thread.sleep(ThreadLocalRandom.current().nextInt(200, 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return results;
    }
    
    public Map<String, Object> getStrategyMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // 전략 메트릭스
        metrics.put("strategyName", "IDOR");
        metrics.put("successRate", 0.42);
        metrics.put("detectionRate", 0.58);
        metrics.put("averageRiskScore", 0.75);
        metrics.put("vectorCount", IdorVector.values().length);
        metrics.put("resourceTypeCount", ResourceType.values().length);
        
        // 벡터별 성공률
        Map<String, Double> vectorSuccessRates = new HashMap<>();
        vectorSuccessRates.put("SEQUENTIAL_ID", 0.60);
        vectorSuccessRates.put("UUID_PREDICTION", 0.15);
        vectorSuccessRates.put("PARAMETER_TAMPERING", 0.45);
        vectorSuccessRates.put("PATH_TRAVERSAL", 0.35);
        vectorSuccessRates.put("REFERENCE_MANIPULATION", 0.50);
        vectorSuccessRates.put("HIDDEN_FIELD_MANIPULATION", 0.40);
        vectorSuccessRates.put("COOKIE_MANIPULATION", 0.30);
        vectorSuccessRates.put("JWT_CLAIM_MANIPULATION", 0.25);
        metrics.put("vectorSuccessRates", vectorSuccessRates);
        
        // 리소스별 위험도
        Map<String, String> resourceRiskLevels = new HashMap<>();
        for (ResourceType type : ResourceType.values()) {
            String riskLevel;
            switch (type) {
                case MEDICAL_RECORD:
                case PAYMENT:
                case ADMIN_PANEL:
                case API_KEY:
                    riskLevel = "CRITICAL";
                    break;
                case USER_PROFILE:
                case INVOICE:
                case ORDER:
                    riskLevel = "HIGH";
                    break;
                default:
                    riskLevel = "MEDIUM";
            }
            resourceRiskLevels.put(type.name(), riskLevel);
        }
        metrics.put("resourceRiskLevels", resourceRiskLevels);
        
        return metrics;
    }
    
    @Override
    public String getSuccessCriteria() {
        return "Successfully access unauthorized resources through direct object reference manipulation";
    }
    
    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.LOW; // IDOR는 낮은 권한에서도 가능
    }
    
    @Override
    public AttackResult execute(AttackContext context) {
        return execute(context.getTargetUser(), context.getParameters());
    }
    
    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.IDOR;
    }
    
    @Override
    public int getPriority() {
        return 75; // 높은 우선순위
    }
    
    @Override
    public AttackCategory getCategory() {
        return AttackCategory.AUTHORIZATION;
    }
    
    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getTargetUser() != null;
    }
    
    @Override
    public long getEstimatedDuration() {
        return 3000; // 3초
    }
    
    @Override
    public String getDescription() {
        return "Insecure Direct Object Reference attacks exploiting weak access controls to access unauthorized resources";
    }
}