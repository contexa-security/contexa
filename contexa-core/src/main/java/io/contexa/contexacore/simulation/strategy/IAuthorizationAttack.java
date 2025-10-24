package io.contexa.contexacore.simulation.strategy;

import java.util.List;
import java.util.Map;

/**
 * 인가 공격 전략 인터페이스
 * 
 * 권한 상승, IDOR, API 권한 우회 등 인가 관련 공격을 정의합니다.
 * @Protectable 리소스에 대한 무단 접근 시도를 시뮬레이션합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
public interface IAuthorizationAttack extends IAttackStrategy {
    
    /**
     * 리소스 접근 시도
     * 
     * @param resource 리소스 경로
     * @param method HTTP 메서드
     * @return 접근 결과
     */
    ResourceAccessResult attemptAccess(String resource, String method);
    
    /**
     * 권한 상승 시도
     * 
     * @param currentRole 현재 역할
     * @param targetRole 목표 역할
     * @return 상승 성공 여부
     */
    boolean attemptPrivilegeEscalation(String currentRole, String targetRole);
    
    /**
     * IDOR (Insecure Direct Object Reference) 공격
     * 
     * @param objectId 원본 객체 ID
     * @param targetObjectId 타겟 객체 ID
     * @return IDOR 공격 결과
     */
    IdorResult attemptIdorAttack(String objectId, String targetObjectId);
    
    /**
     * API 권한 우회 시도
     * 
     * @param apiEndpoint API 엔드포인트
     * @param bypassTechnique 우회 기법
     * @return 우회 성공 여부
     */
    boolean attemptApiBypass(String apiEndpoint, ApiBypassTechnique bypassTechnique);
    
    /**
     * 역할 조작 시도
     * 
     * @param jwtToken JWT 토큰
     * @param newRole 새로운 역할
     * @return 조작된 토큰
     */
    String manipulateRole(String jwtToken, String newRole);
    
    /**
     * 수평적 권한 상승 (다른 사용자의 리소스 접근)
     * 
     * @param userId 현재 사용자 ID
     * @param targetUserId 타겟 사용자 ID
     * @return 접근 성공 여부
     */
    boolean attemptHorizontalEscalation(String userId, String targetUserId);
    
    /**
     * @Protectable 리소스 스캔
     * 
     * @return 발견된 보호된 리소스 목록
     */
    List<ProtectedResource> scanProtectedResources();
    
    /**
     * 권한 매트릭스 분석
     * 
     * @param role 역할
     * @return 권한 매트릭스
     */
    Map<String, List<String>> analyzePermissionMatrix(String role);
    
    /**
     * 리소스 접근 시도 (다중 파라미터)
     * 
     * @param resourceId 리소스 ID
     * @param userId 사용자 ID
     * @param context 공격 컨텍스트
     * @return 리소스 접근 결과
     */
    default ResourceAccessResult attemptResourceAccess(String resourceId, String userId, AttackContext context) {
        ResourceAccessResult result = new ResourceAccessResult();
        result.setAccessible(false);
        result.setHttpStatusCode(403);
        return result;
    }
    
    /**
     * IDOR 공격 실행
     * 
     * @param objectId 객체 ID
     * @param context 공격 컨텍스트
     * @return IDOR 결과
     */
    default IdorResult exploitIdor(String objectId, AttackContext context) {
        IdorResult result = new IdorResult();
        result.setSuccessful(false);
        result.setDetected(true);
        return result;
    }
    
    /**
     * API 권한 우회 시도 (확장)
     * 
     * @param endpoint API 엔드포인트
     * @param context 공격 컨텍스트
     * @return API 우회 결과
     */
    default ApiBypassResult bypassApiAuthorization(String endpoint, AttackContext context) {
        return new ApiBypassResult(endpoint, ApiBypassTechnique.HTTP_METHOD_OVERRIDE, 
                                  false, "Default implementation", null);
    }
    
    /**
     * 리소스 접근 결과
     */
    class ResourceAccessResult {
        private String resourceId;
        private String userId;
        private boolean unauthorizedAttempt;
        private boolean accessible;
        private int httpStatusCode;
        private String responseBody;
        private Map<String, String> responseHeaders;
        private boolean protectedByAi;
        private String denialReason;
        private List<String> triggeredPolicies;
        private Map<String, Object> metadata;
        
        // Constructors
        public ResourceAccessResult() {}
        
        public ResourceAccessResult(String resourceId, String userId, boolean unauthorizedAttempt,
                                   boolean accessible, String denialReason, Map<String, Object> metadata) {
            this.resourceId = resourceId;
            this.userId = userId;
            this.unauthorizedAttempt = unauthorizedAttempt;
            this.accessible = accessible;
            this.denialReason = denialReason;
            this.metadata = metadata;
        }
        
        // Getters and Setters
        public String getResourceId() { return resourceId; }
        public void setResourceId(String resourceId) { this.resourceId = resourceId; }
        
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        
        public boolean isUnauthorizedAttempt() { return unauthorizedAttempt; }
        public void setUnauthorizedAttempt(boolean unauthorizedAttempt) { 
            this.unauthorizedAttempt = unauthorizedAttempt; 
        }
        
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
        public boolean isAccessible() { return accessible; }
        public void setAccessible(boolean accessible) { this.accessible = accessible; }
        
        public int getHttpStatusCode() { return httpStatusCode; }
        public void setHttpStatusCode(int httpStatusCode) { this.httpStatusCode = httpStatusCode; }
        
        public String getResponseBody() { return responseBody; }
        public void setResponseBody(String responseBody) { this.responseBody = responseBody; }
        
        public Map<String, String> getResponseHeaders() { return responseHeaders; }
        public void setResponseHeaders(Map<String, String> responseHeaders) { 
            this.responseHeaders = responseHeaders; 
        }
        
        public boolean isProtectedByAi() { return protectedByAi; }
        public void setProtectedByAi(boolean protectedByAi) { this.protectedByAi = protectedByAi; }
        
        public String getDenialReason() { return denialReason; }
        public void setDenialReason(String denialReason) { this.denialReason = denialReason; }
        
        public List<String> getTriggeredPolicies() { return triggeredPolicies; }
        public void setTriggeredPolicies(List<String> triggeredPolicies) { 
            this.triggeredPolicies = triggeredPolicies; 
        }
    }
    
    /**
     * IDOR 공격 결과
     */
    class IdorResult {
        private String objectId;
        private boolean successful;
        private int responseCode;
        private String accessedData;
        private String dataType;
        private String sensitivity; // LOW, MEDIUM, HIGH, CRITICAL
        private boolean detected;
        private String detectionMethod;
        private String url;
        private String attacker;
        
        // Constructors
        public IdorResult() {}
        
        public IdorResult(String objectId, boolean successful, int responseCode,
                         String accessedData, String url, String attacker) {
            this.objectId = objectId;
            this.successful = successful;
            this.responseCode = responseCode;
            this.accessedData = accessedData;
            this.url = url;
            this.attacker = attacker;
        }
        
        // Getters and Setters
        public String getObjectId() { return objectId; }
        public void setObjectId(String objectId) { this.objectId = objectId; }
        
        public int getResponseCode() { return responseCode; }
        public void setResponseCode(int responseCode) { this.responseCode = responseCode; }
        
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        
        public String getAttacker() { return attacker; }
        public void setAttacker(String attacker) { this.attacker = attacker; }
        public boolean isSuccessful() { return successful; }
        public void setSuccessful(boolean successful) { this.successful = successful; }
        
        public String getAccessedData() { return accessedData; }
        public void setAccessedData(String accessedData) { this.accessedData = accessedData; }
        
        public String getDataType() { return dataType; }
        public void setDataType(String dataType) { this.dataType = dataType; }
        
        public String getSensitivity() { return sensitivity; }
        public void setSensitivity(String sensitivity) { this.sensitivity = sensitivity; }
        
        public boolean isDetected() { return detected; }
        public void setDetected(boolean detected) { this.detected = detected; }
        
        public String getDetectionMethod() { return detectionMethod; }
        public void setDetectionMethod(String detectionMethod) { 
            this.detectionMethod = detectionMethod; 
        }
    }
    
    /**
     * 보호된 리소스
     */
    class ProtectedResource {
        private String path;
        private String httpMethod;
        private String protectionLevel; // @Protectable annotation value
        private boolean aiEvaluation;
        private String riskLevel;
        private List<String> requiredRoles;
        
        // Getters and Setters
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        
        public String getHttpMethod() { return httpMethod; }
        public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }
        
        public String getProtectionLevel() { return protectionLevel; }
        public void setProtectionLevel(String protectionLevel) { 
            this.protectionLevel = protectionLevel; 
        }
        
        public boolean isAiEvaluation() { return aiEvaluation; }
        public void setAiEvaluation(boolean aiEvaluation) { this.aiEvaluation = aiEvaluation; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
        
        public List<String> getRequiredRoles() { return requiredRoles; }
        public void setRequiredRoles(List<String> requiredRoles) { 
            this.requiredRoles = requiredRoles; 
        }
    }
    
    /**
     * API 우회 결과
     */
    class ApiBypassResult {
        private String endpoint;
        private ApiBypassTechnique technique;
        private boolean bypassed;
        private String message;
        private Map<String, Object> details;
        
        public ApiBypassResult(String endpoint, ApiBypassTechnique technique, 
                              boolean bypassed, String message, Map<String, Object> details) {
            this.endpoint = endpoint;
            this.technique = technique;
            this.bypassed = bypassed;
            this.message = message;
            this.details = details;
        }
        
        // Getters and Setters
        public String getEndpoint() { return endpoint; }
        public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
        
        public ApiBypassTechnique getTechnique() { return technique; }
        public void setTechnique(ApiBypassTechnique technique) { this.technique = technique; }
        
        public boolean isBypassed() { return bypassed; }
        public void setBypassed(boolean bypassed) { this.bypassed = bypassed; }
        
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        
        public Map<String, Object> getDetails() { return details; }
        public void setDetails(Map<String, Object> details) { this.details = details; }
    }
    
    /**
     * API 우회 기법
     */
    enum ApiBypassTechnique {
        HTTP_METHOD_OVERRIDE("Change HTTP method (GET to POST, etc.)"),
        HEADER_INJECTION("Inject authorization headers"),
        PARAMETER_POLLUTION("HTTP parameter pollution"),
        PATH_TRAVERSAL("Path traversal in API endpoints"),
        VERSION_DOWNGRADE("Use older API version with weaker security"),
        CONTENT_TYPE_CONFUSION("Confuse content type validation"),
        JWT_ALGORITHM_CONFUSION("JWT algorithm confusion attack"),
        GRAPHQL_INTROSPECTION("GraphQL introspection exploitation"),
        REST_TO_GRAPHQL("Convert REST to GraphQL to bypass restrictions"),
        CASE_SENSITIVITY("Exploit case sensitivity differences");
        
        private final String description;
        
        ApiBypassTechnique(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
}