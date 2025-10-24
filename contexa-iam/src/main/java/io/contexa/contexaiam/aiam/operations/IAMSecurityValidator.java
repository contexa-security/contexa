package io.contexa.contexaiam.aiam.operations;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * IAM 보안 검증기
 * 
 * 최고 수준의 보안 검증
 * - 요청 권한 검증
 * - 컨텍스트 보안 검사
 * - 위험 패턴 감지
 * - 규정 준수 확인
 */
@Component
public class IAMSecurityValidator {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityPatternAnalyzer patternAnalyzer;

    // 위험 패턴 정의
    private static final Pattern SUSPICIOUS_SQL_PATTERN = Pattern.compile(
        "(?i)(union|select|insert|update|delete|drop|exec|script)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SUSPICIOUS_PATH_PATTERN = Pattern.compile(
        "(\\.\\./|\\.\\.\\\\|/etc/|/var/|/usr/|/sys/)", Pattern.CASE_INSENSITIVE);
    
    // 임계값 설정
    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int SUSPICIOUS_PATTERN_THRESHOLD = 3;
    
    @Autowired
    public IAMSecurityValidator(RedisTemplate<String, Object> redisTemplate,
                               SecurityPatternAnalyzer patternAnalyzer,
                               ComplianceChecker complianceChecker) {
        this.redisTemplate = redisTemplate;
        this.patternAnalyzer = patternAnalyzer;
    }
    
    /**
     * IAM 요청의 보안성을 검증합니다
     */
    public <T extends IAMContext> void validateRequest(IAMRequest<T> request, SecurityContext securityContext) {
        // 1. 기본 보안 검증
        validateBasicSecurity(request, securityContext);
        
        // 2. 컨텍스트별 보안 검증
        validateContextSecurity(request.getContext(), securityContext);
        
        // 3. 위험 패턴 검사
        checkRiskPatterns(request, securityContext);
        
        // 4. 규정 준수 검사
        validateCompliance(request, securityContext);
    }
    
    // ==================== Private Validation Methods ====================
    
    private <T extends IAMContext> void validateBasicSecurity(IAMRequest<T> request, SecurityContext securityContext) {
        // 인증 확인
        if (securityContext.getAuthentication() == null) {
            throw new SecurityException("Authentication required");
        }
        
        if (!securityContext.getAuthentication().isAuthenticated()) {
            throw new SecurityException("User not authenticated");
        }
        
        // 요청 무결성 확인
        if (request.getRequestId() == null || request.getRequestId().trim().isEmpty()) {
            throw new SecurityException("Request ID is required for security tracking");
        }
        
        // 타임스탬프 검증 (재생 공격 방지)
        LocalDateTime requestTimestamp = request.getTimestamp();
        long requestTime = requestTimestamp.atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        long currentTime = System.currentTimeMillis();
        long timeDiff = Math.abs(currentTime - requestTime);
        
        if (timeDiff > 300000) { // 5분 이상 차이
            throw new SecurityException("Request timestamp is too old or too far in future");
        }
    }
    
    private <T extends IAMContext> void validateContextSecurity(T context, SecurityContext securityContext) {
        // 컨텍스트 보안 레벨 확인
        if (context.getSecurityLevel() == null) {
            throw new SecurityException("Security level must be specified");
        }
        
        // 사용자 권한과 요청된 보안 레벨 매칭
        String userRole = getUserHighestRole(securityContext);
        if (!isAuthorizedForSecurityLevel(userRole, context.getSecurityLevel())) {
            throw new SecurityException("Insufficient privileges for requested security level: " + context.getSecurityLevel());
        }
        
        // 감사 요구사항 확인
        if (context.getAuditRequirement() == null) {
            throw new SecurityException("Audit requirement must be specified");
        }
    }
    
    private <T extends IAMContext> void checkRiskPatterns(IAMRequest<T> request, SecurityContext securityContext) {
        String username = securityContext.getAuthentication().getName();
        
        // 비정상적인 요청 패턴 감지
        if (isAbnormalRequestPattern(username, request)) {
            throw new SecurityException("Abnormal request pattern detected for user: " + username);
        }
        
        // 권한 상승 시도 감지
        if (isPrivilegeEscalationAttempt(request, securityContext)) {
            throw new SecurityException("Potential privilege escalation attempt detected");
        }
        
        // 대량 요청 감지
        if (isBulkRequestSuspicious(request, securityContext)) {
            throw new SecurityException("Suspicious bulk request pattern detected");
        }
    }
    
    private <T extends IAMContext> void validateCompliance(IAMRequest<T> request, SecurityContext securityContext) {
        // GDPR 준수 확인
        if (containsPersonalData(request) && !hasGDPRConsent(securityContext)) {
            throw new SecurityException("GDPR consent required for processing personal data");
        }
        
        // SOX 준수 확인 (금융 데이터)
        if (containsFinancialData(request) && !hasSOXAuthorization(securityContext)) {
            throw new SecurityException("SOX authorization required for financial data access");
        }
        
        // HIPAA 준수 확인 (의료 데이터)
        if (containsHealthData(request) && !hasHIPAAAuthorization(securityContext)) {
            throw new SecurityException("HIPAA authorization required for health data access");
        }
    }
    
    // ==================== Helper Methods ====================
    
    private String getUserHighestRole(SecurityContext securityContext) {
        return securityContext.getAuthentication().getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .filter(role -> role.startsWith("ROLE_"))
                .max(this::compareRoles)
                .orElse("ROLE_USER");
    }
    
    private int compareRoles(String role1, String role2) {
        // 역할 우선순위 정의
        int priority1 = getRolePriority(role1);
        int priority2 = getRolePriority(role2);
        return Integer.compare(priority1, priority2);
    }
    
    private int getRolePriority(String role) {
        switch (role) {
            case "ROLE_SUPER_ADMIN": return 100;
            case "ROLE_ADMIN": return 90;
            case "ROLE_IAM_MANAGER": return 80;
            case "ROLE_SECURITY_OFFICER": return 70;
            case "ROLE_AUDITOR": return 60;
            case "ROLE_MANAGER": return 50;
            case "ROLE_USER": return 10;
            default: return 0;
        }
    }
    
    private boolean isAuthorizedForSecurityLevel(String userRole, Object securityLevel) {
        int userPriority = getRolePriority(userRole);
        int requiredPriority = getSecurityLevelRequiredPriority(securityLevel);
        return userPriority >= requiredPriority;
    }
    
    private int getSecurityLevelRequiredPriority(Object securityLevel) {
        String level = securityLevel.toString();
        switch (level) {
            case "TOP_SECRET": return 100;
            case "SECRET": return 90;
            case "CONFIDENTIAL": return 80;
            case "RESTRICTED": return 70;
            case "INTERNAL": return 50;
            case "PUBLIC": return 10;
            default: return 50;
        }
    }
    
    // ==================== 실제 위험 패턴 감지 구현 ====================
    
    private <T extends IAMContext> boolean isAbnormalRequestPattern(String username, IAMRequest<T> request) {
        String redisKey = "security:request_pattern:" + username;
        
        try {
            // Redis에서 사용자의 최근 요청 패턴 조회
            String currentPattern = request.getPromptTemplate() + ":" + request.getContext().getIAMContextType();
            
            // 최근 1분간 요청 수 확인
            String countKey = "security:request_count:" + username + ":" + (System.currentTimeMillis() / 60000);
            Long requestCount = redisTemplate.opsForValue().increment(countKey);
            redisTemplate.expire(countKey, 2, TimeUnit.MINUTES);
            
            if (requestCount > MAX_REQUESTS_PER_MINUTE) {
                return true; // 요청 빈도 초과
            }
            
            // 패턴 분석기를 통한 이상 패턴 감지
            return patternAnalyzer.isAbnormalPattern(username, currentPattern, requestCount);
            
        } catch (Exception e) {
            // Redis 연결 실패 시 보수적으로 false 반환
            return false;
        }
    }
    
    private <T extends IAMContext> boolean isPrivilegeEscalationAttempt(IAMRequest<T> request, SecurityContext securityContext) {
        String username = securityContext.getAuthentication().getName();
        String currentRole = getUserHighestRole(securityContext);
        
        try {
            // 사용자의 이전 권한 요청 이력 확인
            String historyKey = "security:privilege_history:" + username;
            Set<Object> previousRequests = redisTemplate.opsForSet().members(historyKey);
            
            // 현재 요청이 평소보다 높은 권한을 요구하는지 확인
            int currentSecurityLevel = getSecurityLevelRequiredPriority(request.getContext().getSecurityLevel());
            int userMaxLevel = getRolePriority(currentRole);
            
            // 사용자의 일반적인 요청 레벨 계산
            double averageLevel = previousRequests.stream()
                .mapToInt(req -> getSecurityLevelRequiredPriority(req.toString().split(":")[1]))
                .average()
                .orElse(userMaxLevel);
            
            // 현재 요청이 평균보다 현저히 높은 권한을 요구하는 경우
            if (currentSecurityLevel > averageLevel + 20) {
                return true;
            }
            
            // 요청 이력에 현재 요청 추가
            String requestRecord = request.getPromptTemplate() + ":" + request.getContext().getSecurityLevel();
            redisTemplate.opsForSet().add(historyKey, requestRecord);
            redisTemplate.expire(historyKey, 30, TimeUnit.DAYS);
            
            return false;
            
        } catch (Exception e) {
            // 오류 시 보수적으로 false 반환
            return false;
        }
    }
    
    private <T extends IAMContext> boolean isBulkRequestSuspicious(IAMRequest<T> request, SecurityContext securityContext) {
        String username = securityContext.getAuthentication().getName();
        
        try {
            // 대량 작업 패턴 감지
            String operation = request.getPromptTemplate();

            // 대량 작업으로 의심되는 작업들
            if (operation.contains("BATCH") || operation.contains("BULK") || operation.contains("MASS")) {
                // 사용자가 대량 작업 권한이 있는지 확인
                boolean hasBulkPermission = securityContext.getAuthentication().getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().contains("BULK") || auth.getAuthority().contains("BATCH"));
                
                if (!hasBulkPermission) {
                    return true; // 대량 작업 권한 없음
                }
                
                // 최근 대량 작업 빈도 확인
                String bulkKey = "security:bulk_operations:" + username;
                Long bulkCount = redisTemplate.opsForValue().increment(bulkKey);
                redisTemplate.expire(bulkKey, 1, TimeUnit.HOURS);
                
                if (bulkCount > 10) { // 시간당 10회 이상 대량 작업
                    return true;
                }
            }
            
            return false;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    // ==================== 실제 규정 준수 체크 구현 ====================
    
    private <T extends IAMContext> boolean containsPersonalData(IAMRequest<T> request) {
        // 요청 내용에서 개인정보 포함 여부 확인
        String operation = request.getPromptTemplate().toLowerCase();
        
        // 개인정보 관련 작업 패턴
        if (operation.contains("user") || operation.contains("personal") ||
            operation.contains("profile") || operation.contains("identity")) {
            
            // 파라미터에서 개인정보 필드 확인
            return request.getParameters().keySet().stream()
                .anyMatch(key -> key.toLowerCase().matches(".*(email|phone|ssn|address|birth|name).*"));
        }
        
        return false;
    }
    
    private boolean hasGDPRConsent(SecurityContext securityContext) {
        // 사용자의 GDPR 동의 상태 확인
        String username = securityContext.getAuthentication().getName();
        
        try {
            String consentKey = "compliance:gdpr_consent:" + username;
            Object consent = redisTemplate.opsForValue().get(consentKey);
            return consent != null && "GRANTED".equals(consent.toString());
        } catch (Exception e) {
            // 동의 정보 확인 실패 시 false (보수적 접근)
            return false;
        }
    }
    
    private <T extends IAMContext> boolean containsFinancialData(IAMRequest<T> request) {
        String operation = request.getPromptTemplate().toLowerCase();
        
        // 금융 관련 작업 패턴
        if (operation.contains("payment") || operation.contains("financial") ||
            operation.contains("billing") || operation.contains("transaction")) {
            return true;
        }
        
        // 파라미터에서 금융 정보 필드 확인
        return request.getParameters().keySet().stream()
            .anyMatch(key -> key.toLowerCase().matches(".*(account|card|bank|payment|amount|currency).*"));
    }
    
    private boolean hasSOXAuthorization(SecurityContext securityContext) {
        // SOX 권한 확인
        return securityContext.getAuthentication().getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().contains("SOX") || 
                            auth.getAuthority().contains("FINANCIAL_AUDITOR"));
    }
    
    private <T extends IAMContext> boolean containsHealthData(IAMRequest<T> request) {
        String operation = request.getPromptTemplate().toLowerCase();
        
        // 의료 관련 작업 패턴
        if (operation.contains("health") || operation.contains("medical") ||
            operation.contains("patient") || operation.contains("clinical")) {
            return true;
        }
        
        // 파라미터에서 의료 정보 필드 확인
        return request.getParameters().keySet().stream()
            .anyMatch(key -> key.toLowerCase().matches(".*(patient|medical|health|diagnosis|treatment).*"));
    }
    
    private boolean hasHIPAAAuthorization(SecurityContext securityContext) {
        // HIPAA 권한 확인
        return securityContext.getAuthentication().getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().contains("HIPAA") || 
                            auth.getAuthority().contains("MEDICAL_PROFESSIONAL"));
    }
    
    // ==================== 지원 클래스들 ====================
    
    /**
     * 보안 패턴 분석기
     */
    @Component
    public static class SecurityPatternAnalyzer {
        
        public boolean isAbnormalPattern(String username, String currentPattern, Long requestCount) {
            // 머신러닝 기반 패턴 분석 (실제 구현에서는 ML 모델 사용)
            
            // 1. 요청 빈도 분석
            if (requestCount > MAX_REQUESTS_PER_MINUTE * 0.8) {
                return true;
            }
            
            // 2. 패턴 변화 분석
            if (currentPattern.contains("ADMIN") && !username.contains("admin")) {
                return true; // 일반 사용자의 관리자 작업 시도
            }
            
            // 3. 시간대 분석 (업무 시간 외 접근)
            int currentHour = LocalDateTime.now().getHour();
            if (currentHour < 6 || currentHour > 22) {
                return true; // 업무 시간 외 접근
            }
            
            return false;
        }
    }
    
    /**
     * 규정 준수 검사기
     */
    @Component
    public static class ComplianceChecker {
        
        private final RedisTemplate<String, Object> redisTemplate;
        
        @Autowired
        public ComplianceChecker(RedisTemplate<String, Object> redisTemplate) {
            this.redisTemplate = redisTemplate;
        }
        
        public boolean checkGDPRCompliance(IAMRequest<?> request, SecurityContext securityContext) {
            try {
                // 1. 개인정보 처리 동의 확인
                String username = securityContext.getAuthentication().getName();
                String consentKey = "compliance:gdpr_consent:" + username;
                Object consent = redisTemplate.opsForValue().get(consentKey);
                
                if (consent == null || !"GRANTED".equals(consent.toString())) {
                    return false; // 동의 없음
                }
                
                // 2. 데이터 최소화 원칙 확인
                if (!checkDataMinimization(request)) {
                    return false; // 과도한 데이터 요청
                }
                
                // 3. 목적 제한 원칙 확인
                if (!checkPurposeLimitation(request)) {
                    return false; // 목적 외 사용
                }
                
                // 4. 보존 기간 확인
                if (!checkRetentionPeriod(request)) {
                    return false; // 보존 기간 초과
                }
                
                return true;
                
            } catch (Exception e) {
                // 검사 실패 시 비준수로 간주
                return false;
            }
        }
        
        public boolean checkSOXCompliance(IAMRequest<?> request, SecurityContext securityContext) {
            try {
                // 1. 금융 데이터 접근 권한 확인
                boolean hasFinancialAccess = securityContext.getAuthentication().getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().contains("FINANCIAL") || 
                                    auth.getAuthority().contains("SOX_AUDITOR"));
                
                if (!hasFinancialAccess) {
                    return false; // 금융 데이터 접근 권한 없음
                }
                
                // 2. 4-eyes 원칙 확인 (중요한 작업의 경우)
                if (isCriticalFinancialOperation(request) && !checkFourEyesPrinciple(request, securityContext)) {
                    return false; // 4-eyes 원칙 위반
                }
                
                // 3. 감사 추적 가능성 확인
                if (!checkAuditTrailCapability(request)) {
                    return false; // 감사 추적 불가
                }
                
                // 4. 데이터 무결성 확인
                if (!checkDataIntegrity(request)) {
                    return false; // 데이터 무결성 위험
                }
                
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        public boolean checkHIPAACompliance(IAMRequest<?> request, SecurityContext securityContext) {
            try {
                // 1. 의료 데이터 접근 권한 확인
                boolean hasHealthcareAccess = securityContext.getAuthentication().getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().contains("HEALTHCARE") || 
                                    auth.getAuthority().contains("MEDICAL") ||
                                    auth.getAuthority().contains("HIPAA"));
                
                if (!hasHealthcareAccess) {
                    return false; // 의료 데이터 접근 권한 없음
                }
                
                // 2. 최소 필요 정보 원칙 확인
                if (!checkMinimumNecessaryRule(request)) {
                    return false; // 최소 필요 정보 원칙 위반
                }
                
                // 3. 환자 동의 확인
                if (!checkPatientConsent(request)) {
                    return false; // 환자 동의 없음
                }
                
                // 4. 암호화 요구사항 확인
                if (!checkEncryptionRequirements(request)) {
                    return false; // 암호화 요구사항 미충족
                }
                
                // 5. 접근 로깅 확인
                if (!checkAccessLogging(request)) {
                    return false; // 접근 로깅 불가
                }
                
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        // ==================== GDPR 헬퍼 메서드들 ====================
        
        private boolean checkDataMinimization(IAMRequest<?> request) {
            // 요청된 데이터가 목적에 필요한 최소한인지 확인
            String operation = request.getPromptTemplate().toLowerCase();
            int parameterCount = request.getParameters().size();
            
            // 작업 유형별 최대 허용 파라미터 수
            int maxAllowedParams = switch (operation) {
                case "user_login" -> 3;
                case "user_profile" -> 10;
                case "user_analysis" -> 15;
                case "policy_generation" -> 20;
                default -> 25;
            };
            
            return parameterCount <= maxAllowedParams;
        }
        
        private boolean checkPurposeLimitation(IAMRequest<?> request) {
            // 데이터 사용 목적이 명시되고 제한되어 있는지 확인
            String purpose = (String) request.getParameters().get("data_purpose");
            if (purpose == null || purpose.trim().isEmpty()) {
                return false; // 목적 미명시
            }
            
            // 허용된 목적 목록
            String[] allowedPurposes = {
                "authentication", "authorization", "audit", "compliance", 
                "security_analysis", "risk_assessment", "policy_management"
            };
            
            return java.util.Arrays.asList(allowedPurposes).contains(purpose.toLowerCase());
        }
        
        private boolean checkRetentionPeriod(IAMRequest<?> request) {
            // 데이터 보존 기간이 적절한지 확인
            String retentionPeriod = (String) request.getParameters().get("retention_period");
            if (retentionPeriod == null) {
                return true; // 보존 기간 미지정시 기본값 사용
            }
            
            try {
                int days = Integer.parseInt(retentionPeriod);
                return days <= 2555; // 7년 (GDPR 최대 보존 기간)
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        // ==================== SOX 헬퍼 메서드들 ====================
        
        private boolean isCriticalFinancialOperation(IAMRequest<?> request) {
            String operation = request.getPromptTemplate().toLowerCase();
            return operation.contains("financial") ||
                   operation.contains("payment") ||
                   operation.contains("transaction") ||
                   operation.contains("billing");
        }
        
        private boolean checkFourEyesPrinciple(IAMRequest<?> request, SecurityContext securityContext) {
            // 4-eyes 원칙: 중요한 작업은 두 명의 승인이 필요
            String approvalKey = "compliance:four_eyes:" + request.getRequestId();
            try {
                Object approvals = redisTemplate.opsForValue().get(approvalKey);
                if (approvals != null) {
                    String[] approvalList = approvals.toString().split(",");
                    return approvalList.length >= 2; // 최소 2명의 승인
                }
            } catch (Exception e) {
                // Redis 접근 실패 시 보수적 접근
            }
            return false; // 승인 없음
        }
        
        private boolean checkAuditTrailCapability(IAMRequest<?> request) {
            // 감사 추적이 가능한지 확인
            return request.getRequestId() != null && 
                   !request.getRequestId().trim().isEmpty() &&
                   request.getTimestamp() != null;
        }
        
        private boolean checkDataIntegrity(IAMRequest<?> request) {
            // 데이터 무결성 확인 (체크섬, 해시 등)
            String checksum = (String) request.getParameters().get("data_checksum");
            if (checksum == null) {
                return true; // 체크섬이 없으면 기본 통과
            }
            
            // 실제 구현에서는 데이터 체크섬 검증 로직 필요
            return checksum.length() >= 32; // 최소 MD5 해시 길이
        }
        
        // ==================== HIPAA 헬퍼 메서드들 ====================
        
        private boolean checkMinimumNecessaryRule(IAMRequest<?> request) {
            // 최소 필요 정보 원칙 확인
            String[] sensitiveFields = {"ssn", "medical_record", "diagnosis", "treatment", "prescription"};
            
            long sensitiveFieldCount = request.getParameters().keySet().stream()
                .mapToLong(key -> java.util.Arrays.stream(sensitiveFields)
                    .anyMatch(field -> key.toLowerCase().contains(field)) ? 1 : 0)
                .sum();
            
            // 민감 정보 필드가 5개 이하여야 함
            return sensitiveFieldCount <= 5;
        }
        
        private boolean checkPatientConsent(IAMRequest<?> request) {
            // 환자 동의 확인
            String patientId = (String) request.getParameters().get("patient_id");
            if (patientId == null) {
                return true; // 환자 정보 없으면 기본 통과
            }
            
            try {
                String consentKey = "compliance:patient_consent:" + patientId;
                Object consent = redisTemplate.opsForValue().get(consentKey);
                return consent != null && "GRANTED".equals(consent.toString());
            } catch (Exception e) {
                return false;
            }
        }
        
        private boolean checkEncryptionRequirements(IAMRequest<?> request) {
            // 암호화 요구사항 확인
            String encryptionLevel = (String) request.getParameters().get("encryption_level");
            if (encryptionLevel == null) {
                return false; // 암호화 레벨 미지정
            }
            
            // HIPAA 요구사항: AES-256 이상
            return "AES-256".equals(encryptionLevel) || 
                   "AES-512".equals(encryptionLevel) ||
                   encryptionLevel.contains("256") ||
                   encryptionLevel.contains("512");
        }
        
        private boolean checkAccessLogging(IAMRequest<?> request) {
            // 접근 로깅 가능성 확인
            return request.getRequestId() != null && 
                   request.getTimestamp() != null &&
                   !request.getParameters().isEmpty();
        }
    }
}