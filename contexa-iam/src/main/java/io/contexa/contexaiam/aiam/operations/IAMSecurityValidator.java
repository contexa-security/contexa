package io.contexa.contexaiam.aiam.operations;

import io.contexa.contexacommon.domain.context.IAMContext;
import io.contexa.contexacommon.domain.request.IAMRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.context.SecurityContext;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;


public class IAMSecurityValidator {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityPatternAnalyzer patternAnalyzer;

    
    private static final Pattern SUSPICIOUS_SQL_PATTERN = Pattern.compile(
        "(?i)(union|select|insert|update|delete|drop|exec|script)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SUSPICIOUS_PATH_PATTERN = Pattern.compile(
        "(\\.\\./|\\.\\.\\\\|/etc/|/var/|/usr/|/sys/)", Pattern.CASE_INSENSITIVE);
    
    
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
    
    
    public <T extends IAMContext> void validateRequest(IAMRequest<T> request, SecurityContext securityContext) {
        
        validateBasicSecurity(request, securityContext);
        
        
        validateContextSecurity(request.getContext(), securityContext);
        
        
        checkRiskPatterns(request, securityContext);
        
        
        validateCompliance(request, securityContext);
    }
    
    
    
    private <T extends IAMContext> void validateBasicSecurity(IAMRequest<T> request, SecurityContext securityContext) {
        
        if (securityContext.getAuthentication() == null) {
            throw new SecurityException("Authentication required");
        }
        
        if (!securityContext.getAuthentication().isAuthenticated()) {
            throw new SecurityException("User not authenticated");
        }
        
        
        if (request.getRequestId() == null || request.getRequestId().trim().isEmpty()) {
            throw new SecurityException("Request ID is required for security tracking");
        }
        
        
        LocalDateTime requestTimestamp = request.getTimestamp();
        long requestTime = requestTimestamp.atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        long currentTime = System.currentTimeMillis();
        long timeDiff = Math.abs(currentTime - requestTime);
        
        if (timeDiff > 300000) { 
            throw new SecurityException("Request timestamp is too old or too far in future");
        }
    }
    
    private <T extends IAMContext> void validateContextSecurity(T context, SecurityContext securityContext) {
        
        if (context.getSecurityLevel() == null) {
            throw new SecurityException("Security level must be specified");
        }
        
        
        String userRole = getUserHighestRole(securityContext);
        if (!isAuthorizedForSecurityLevel(userRole, context.getSecurityLevel())) {
            throw new SecurityException("Insufficient privileges for requested security level: " + context.getSecurityLevel());
        }
        
        
        if (context.getAuditRequirement() == null) {
            throw new SecurityException("Audit requirement must be specified");
        }
    }
    
    private <T extends IAMContext> void checkRiskPatterns(IAMRequest<T> request, SecurityContext securityContext) {
        String username = securityContext.getAuthentication().getName();
        
        
        if (isAbnormalRequestPattern(username, request)) {
            throw new SecurityException("Abnormal request pattern detected for user: " + username);
        }
        
        
        if (isPrivilegeEscalationAttempt(request, securityContext)) {
            throw new SecurityException("Potential privilege escalation attempt detected");
        }
        
        
        if (isBulkRequestSuspicious(request, securityContext)) {
            throw new SecurityException("Suspicious bulk request pattern detected");
        }
    }
    
    private <T extends IAMContext> void validateCompliance(IAMRequest<T> request, SecurityContext securityContext) {
        
        if (containsPersonalData(request) && !hasGDPRConsent(securityContext)) {
            throw new SecurityException("GDPR consent required for processing personal data");
        }
        
        
        if (containsFinancialData(request) && !hasSOXAuthorization(securityContext)) {
            throw new SecurityException("SOX authorization required for financial data access");
        }
        
        
        if (containsHealthData(request) && !hasHIPAAAuthorization(securityContext)) {
            throw new SecurityException("HIPAA authorization required for health data access");
        }
    }
    
    
    
    private String getUserHighestRole(SecurityContext securityContext) {
        return securityContext.getAuthentication().getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .filter(role -> role.startsWith("ROLE_"))
                .max(this::compareRoles)
                .orElse("ROLE_USER");
    }
    
    private int compareRoles(String role1, String role2) {
        
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
    
    
    
    private <T extends IAMContext> boolean isAbnormalRequestPattern(String username, IAMRequest<T> request) {
        String redisKey = "security:request_pattern:" + username;
        
        try {
            
            String currentPattern = request.getPromptTemplate() + ":" + request.getContext().getIAMContextType();
            
            
            String countKey = "security:request_count:" + username + ":" + (System.currentTimeMillis() / 60000);
            Long requestCount = redisTemplate.opsForValue().increment(countKey);
            redisTemplate.expire(countKey, 2, TimeUnit.MINUTES);
            
            if (requestCount > MAX_REQUESTS_PER_MINUTE) {
                return true; 
            }
            
            
            return patternAnalyzer.isAbnormalPattern(username, currentPattern, requestCount);
            
        } catch (Exception e) {
            
            return false;
        }
    }
    
    private <T extends IAMContext> boolean isPrivilegeEscalationAttempt(IAMRequest<T> request, SecurityContext securityContext) {
        String username = securityContext.getAuthentication().getName();
        String currentRole = getUserHighestRole(securityContext);
        
        try {
            
            String historyKey = "security:privilege_history:" + username;
            Set<Object> previousRequests = redisTemplate.opsForSet().members(historyKey);
            
            
            int currentSecurityLevel = getSecurityLevelRequiredPriority(request.getContext().getSecurityLevel());
            int userMaxLevel = getRolePriority(currentRole);
            
            
            double averageLevel = previousRequests.stream()
                .mapToInt(req -> getSecurityLevelRequiredPriority(req.toString().split(":")[1]))
                .average()
                .orElse(userMaxLevel);
            
            
            if (currentSecurityLevel > averageLevel + 20) {
                return true;
            }
            
            
            String requestRecord = request.getPromptTemplate() + ":" + request.getContext().getSecurityLevel();
            redisTemplate.opsForSet().add(historyKey, requestRecord);
            redisTemplate.expire(historyKey, 30, TimeUnit.DAYS);
            
            return false;
            
        } catch (Exception e) {
            
            return false;
        }
    }
    
    private <T extends IAMContext> boolean isBulkRequestSuspicious(IAMRequest<T> request, SecurityContext securityContext) {
        String username = securityContext.getAuthentication().getName();
        
        try {
            
            String operation = request.getPromptTemplate();

            
            if (operation.contains("BATCH") || operation.contains("BULK") || operation.contains("MASS")) {
                
                boolean hasBulkPermission = securityContext.getAuthentication().getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().contains("BULK") || auth.getAuthority().contains("BATCH"));
                
                if (!hasBulkPermission) {
                    return true; 
                }
                
                
                String bulkKey = "security:bulk_operations:" + username;
                Long bulkCount = redisTemplate.opsForValue().increment(bulkKey);
                redisTemplate.expire(bulkKey, 1, TimeUnit.HOURS);
                
                if (bulkCount > 10) { 
                    return true;
                }
            }
            
            return false;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    
    
    private <T extends IAMContext> boolean containsPersonalData(IAMRequest<T> request) {
        
        String operation = request.getPromptTemplate().toLowerCase();
        
        
        if (operation.contains("user") || operation.contains("personal") ||
            operation.contains("profile") || operation.contains("identity")) {
            
            
            return request.getParameters().keySet().stream()
                .anyMatch(key -> key.toLowerCase().matches(".*(email|phone|ssn|address|birth|name).*"));
        }
        
        return false;
    }
    
    private boolean hasGDPRConsent(SecurityContext securityContext) {
        
        String username = securityContext.getAuthentication().getName();
        
        try {
            String consentKey = "compliance:gdpr_consent:" + username;
            Object consent = redisTemplate.opsForValue().get(consentKey);
            return consent != null && "GRANTED".equals(consent.toString());
        } catch (Exception e) {
            
            return false;
        }
    }
    
    private <T extends IAMContext> boolean containsFinancialData(IAMRequest<T> request) {
        String operation = request.getPromptTemplate().toLowerCase();
        
        
        if (operation.contains("payment") || operation.contains("financial") ||
            operation.contains("billing") || operation.contains("transaction")) {
            return true;
        }
        
        
        return request.getParameters().keySet().stream()
            .anyMatch(key -> key.toLowerCase().matches(".*(account|card|bank|payment|amount|currency).*"));
    }
    
    private boolean hasSOXAuthorization(SecurityContext securityContext) {
        
        return securityContext.getAuthentication().getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().contains("SOX") || 
                            auth.getAuthority().contains("FINANCIAL_AUDITOR"));
    }
    
    private <T extends IAMContext> boolean containsHealthData(IAMRequest<T> request) {
        String operation = request.getPromptTemplate().toLowerCase();
        
        
        if (operation.contains("health") || operation.contains("medical") ||
            operation.contains("patient") || operation.contains("clinical")) {
            return true;
        }
        
        
        return request.getParameters().keySet().stream()
            .anyMatch(key -> key.toLowerCase().matches(".*(patient|medical|health|diagnosis|treatment).*"));
    }
    
    private boolean hasHIPAAAuthorization(SecurityContext securityContext) {
        
        return securityContext.getAuthentication().getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().contains("HIPAA") || 
                            auth.getAuthority().contains("MEDICAL_PROFESSIONAL"));
    }
    
    
    
    
    public static class SecurityPatternAnalyzer {
        
        public boolean isAbnormalPattern(String username, String currentPattern, Long requestCount) {
            
            
            
            if (requestCount > MAX_REQUESTS_PER_MINUTE * 0.8) {
                return true;
            }
            
            
            if (currentPattern.contains("ADMIN") && !username.contains("admin")) {
                return true; 
            }
            
            
            int currentHour = LocalDateTime.now().getHour();
            if (currentHour < 6 || currentHour > 22) {
                return true; 
            }
            
            return false;
        }
    }
    
    
    public static class ComplianceChecker {
        
        private final RedisTemplate<String, Object> redisTemplate;
        
        @Autowired
        public ComplianceChecker(RedisTemplate<String, Object> redisTemplate) {
            this.redisTemplate = redisTemplate;
        }
        
        public boolean checkGDPRCompliance(IAMRequest<?> request, SecurityContext securityContext) {
            try {
                
                String username = securityContext.getAuthentication().getName();
                String consentKey = "compliance:gdpr_consent:" + username;
                Object consent = redisTemplate.opsForValue().get(consentKey);
                
                if (consent == null || !"GRANTED".equals(consent.toString())) {
                    return false; 
                }
                
                
                if (!checkDataMinimization(request)) {
                    return false; 
                }
                
                
                if (!checkPurposeLimitation(request)) {
                    return false; 
                }
                
                
                if (!checkRetentionPeriod(request)) {
                    return false; 
                }
                
                return true;
                
            } catch (Exception e) {
                
                return false;
            }
        }
        
        public boolean checkSOXCompliance(IAMRequest<?> request, SecurityContext securityContext) {
            try {
                
                boolean hasFinancialAccess = securityContext.getAuthentication().getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().contains("FINANCIAL") || 
                                    auth.getAuthority().contains("SOX_AUDITOR"));
                
                if (!hasFinancialAccess) {
                    return false; 
                }
                
                
                if (isCriticalFinancialOperation(request) && !checkFourEyesPrinciple(request, securityContext)) {
                    return false; 
                }
                
                
                if (!checkAuditTrailCapability(request)) {
                    return false; 
                }
                
                
                if (!checkDataIntegrity(request)) {
                    return false; 
                }
                
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        public boolean checkHIPAACompliance(IAMRequest<?> request, SecurityContext securityContext) {
            try {
                
                boolean hasHealthcareAccess = securityContext.getAuthentication().getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().contains("HEALTHCARE") || 
                                    auth.getAuthority().contains("MEDICAL") ||
                                    auth.getAuthority().contains("HIPAA"));
                
                if (!hasHealthcareAccess) {
                    return false; 
                }
                
                
                if (!checkMinimumNecessaryRule(request)) {
                    return false; 
                }
                
                
                if (!checkPatientConsent(request)) {
                    return false; 
                }
                
                
                if (!checkEncryptionRequirements(request)) {
                    return false; 
                }
                
                
                if (!checkAccessLogging(request)) {
                    return false; 
                }
                
                return true;
                
            } catch (Exception e) {
                return false;
            }
        }
        
        
        
        private boolean checkDataMinimization(IAMRequest<?> request) {
            
            String operation = request.getPromptTemplate().toLowerCase();
            int parameterCount = request.getParameters().size();
            
            
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
            
            String purpose = (String) request.getParameters().get("data_purpose");
            if (purpose == null || purpose.trim().isEmpty()) {
                return false; 
            }
            
            
            String[] allowedPurposes = {
                "authentication", "authorization", "audit", "compliance", 
                "security_analysis", "risk_assessment", "policy_management"
            };
            
            return java.util.Arrays.asList(allowedPurposes).contains(purpose.toLowerCase());
        }
        
        private boolean checkRetentionPeriod(IAMRequest<?> request) {
            
            String retentionPeriod = (String) request.getParameters().get("retention_period");
            if (retentionPeriod == null) {
                return true; 
            }
            
            try {
                int days = Integer.parseInt(retentionPeriod);
                return days <= 2555; 
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        
        
        private boolean isCriticalFinancialOperation(IAMRequest<?> request) {
            String operation = request.getPromptTemplate().toLowerCase();
            return operation.contains("financial") ||
                   operation.contains("payment") ||
                   operation.contains("transaction") ||
                   operation.contains("billing");
        }
        
        private boolean checkFourEyesPrinciple(IAMRequest<?> request, SecurityContext securityContext) {
            
            String approvalKey = "compliance:four_eyes:" + request.getRequestId();
            try {
                Object approvals = redisTemplate.opsForValue().get(approvalKey);
                if (approvals != null) {
                    String[] approvalList = approvals.toString().split(",");
                    return approvalList.length >= 2; 
                }
            } catch (Exception e) {
                
            }
            return false; 
        }
        
        private boolean checkAuditTrailCapability(IAMRequest<?> request) {
            
            return request.getRequestId() != null && 
                   !request.getRequestId().trim().isEmpty() &&
                   request.getTimestamp() != null;
        }
        
        private boolean checkDataIntegrity(IAMRequest<?> request) {
            
            String checksum = (String) request.getParameters().get("data_checksum");
            if (checksum == null) {
                return true; 
            }
            
            
            return checksum.length() >= 32; 
        }
        
        
        
        private boolean checkMinimumNecessaryRule(IAMRequest<?> request) {
            
            String[] sensitiveFields = {"ssn", "medical_record", "diagnosis", "treatment", "prescription"};
            
            long sensitiveFieldCount = request.getParameters().keySet().stream()
                .mapToLong(key -> java.util.Arrays.stream(sensitiveFields)
                    .anyMatch(field -> key.toLowerCase().contains(field)) ? 1 : 0)
                .sum();
            
            
            return sensitiveFieldCount <= 5;
        }
        
        private boolean checkPatientConsent(IAMRequest<?> request) {
            
            String patientId = (String) request.getParameters().get("patient_id");
            if (patientId == null) {
                return true; 
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
            
            String encryptionLevel = (String) request.getParameters().get("encryption_level");
            if (encryptionLevel == null) {
                return false; 
            }
            
            
            return "AES-256".equals(encryptionLevel) || 
                   "AES-512".equals(encryptionLevel) ||
                   encryptionLevel.contains("256") ||
                   encryptionLevel.contains("512");
        }
        
        private boolean checkAccessLogging(IAMRequest<?> request) {
            
            return request.getRequestId() != null && 
                   request.getTimestamp() != null &&
                   !request.getParameters().isEmpty();
        }
    }
}