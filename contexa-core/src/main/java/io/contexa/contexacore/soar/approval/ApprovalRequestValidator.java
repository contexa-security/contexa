package io.contexa.contexacore.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacore.domain.ApprovalRequest.RiskLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * ApprovalRequest 유효성 검증 클래스
 * 
 * ApprovalRequest의 필수 필드를 검증하고, 누락된 필드를 기본값으로 채우며,
 * 비즈니스 규칙을 적용합니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApprovalRequestValidator {
    
    private static final String DEFAULT_ORGANIZATION_ID = "default-org";
    private static final String DEFAULT_REQUESTED_BY = "system";
    private static final Integer DEFAULT_APPROVAL_TIMEOUT = 300; // 5분
    
    /**
     * ApprovalRequest 검증 및 sanitize
     * 
     * @param request 검증할 요청
     * @return 검증 결과
     */
    public ValidationResult validateAndSanitize(ApprovalRequest request) {
        if (request == null) {
            return ValidationResult.failure("ApprovalRequest is null");
        }
        
        log.debug("Validating ApprovalRequest: {}", request.getRequestId());
        
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        
        // 1. 필수 필드 검증
        validateRequiredFields(request, errors);
        
        // 2. 누락된 필드 기본값 설정
        sanitizeFields(request, warnings);
        
        // 3. 비즈니스 규칙 검증
        validateBusinessRules(request, errors, warnings);
        
        // 4. 데이터 일관성 검증
        validateDataConsistency(request, errors, warnings);
        
        // 결과 생성
        if (!errors.isEmpty()) {
            log.error("Validation failed for request {}: {}", 
                request.getRequestId(), errors);
            return ValidationResult.failure(errors, warnings);
        }
        
        if (!warnings.isEmpty()) {
            log.warn("Validation warnings for request {}: {}", 
                request.getRequestId(), warnings);
        }
        
        log.info("Validation successful for request: {}", request.getRequestId());
        return ValidationResult.success(warnings);
    }
    
    /**
     * 필수 필드 검증
     * 
     * @param request 검증할 요청
     * @param errors 에러 목록
     */
    private void validateRequiredFields(ApprovalRequest request, List<String> errors) {
        // requestId 검증
        if (request.getRequestId() == null || request.getRequestId().trim().isEmpty()) {
            errors.add("requestId is required");
        }
        
        // toolName 검증
        if (request.getToolName() == null || request.getToolName().trim().isEmpty()) {
            errors.add("toolName is required");
        }
        
        // status 검증
        if (request.getStatus() == null) {
            errors.add("status is required");
        }
        
        // riskLevel 검증
        if (request.getRiskLevel() == null) {
            errors.add("riskLevel is required");
        }
        
        // requestedAt 검증
        if (request.getRequestedAt() == null) {
            errors.add("requestedAt is required");
        }
    }
    
    /**
     * 누락된 필드를 기본값으로 설정
     * 
     * @param request 처리할 요청
     * @param warnings 경고 목록
     */
    private void sanitizeFields(ApprovalRequest request, List<String> warnings) {
        // requestId 생성 (필요시)
        if (request.getRequestId() == null || request.getRequestId().trim().isEmpty()) {
            String newId = UUID.randomUUID().toString();
            request.setRequestId(newId);
            warnings.add("Generated new requestId: " + newId);
        }
        
        // status 기본값 설정
        if (request.getStatus() == null) {
            request.setStatus(ApprovalStatus.PENDING);
            warnings.add("Set default status: PENDING");
        }
        
        // riskLevel 기본값 설정
        if (request.getRiskLevel() == null) {
            request.setRiskLevel(RiskLevel.MEDIUM);
            warnings.add("Set default riskLevel: MEDIUM");
        }
        
        // requestedAt 기본값 설정
        if (request.getRequestedAt() == null) {
            request.setRequestedAt(LocalDateTime.now());
            warnings.add("Set requestedAt to current time");
        }
        
        // requestedBy 기본값 설정
        if (request.getRequestedBy() == null || request.getRequestedBy().trim().isEmpty()) {
            request.setRequestedBy(DEFAULT_REQUESTED_BY);
            warnings.add("Set default requestedBy: " + DEFAULT_REQUESTED_BY);
        }
        
        // organizationId 기본값 설정
        if (request.getOrganizationId() == null || request.getOrganizationId().trim().isEmpty()) {
            request.setOrganizationId(DEFAULT_ORGANIZATION_ID);
            warnings.add("Set default organizationId: " + DEFAULT_ORGANIZATION_ID);
        }
        
        // approvalTimeout 기본값 설정
        if (request.getApprovalTimeout() == null || request.getApprovalTimeout() <= 0) {
            request.setApprovalTimeout(DEFAULT_APPROVAL_TIMEOUT);
            warnings.add("Set default approvalTimeout: " + DEFAULT_APPROVAL_TIMEOUT + " seconds");
        }
        
        // requiredApprovers 기본값 설정
        if (request.getRequiredApprovers() == null || request.getRequiredApprovers() < 1) {
            request.setRequiredApprovers(1);
            warnings.add("Set default requiredApprovers: 1");
        }
        
        // Collection 타입 필드 null 체크
        if (request.getRequiredRoles() == null) {
            request.setRequiredRoles(new HashSet<>());
            warnings.add("Initialized empty requiredRoles");
        }
        
        if (request.getParameters() == null) {
            request.setParameters(new HashMap<>());
            warnings.add("Initialized empty parameters");
        }
        
        if (request.getMetadata() == null) {
            request.setMetadata(new HashMap<>());
            warnings.add("Initialized empty metadata");
        }
        
        if (request.getContext() == null) {
            request.setContext(new HashMap<>());
            warnings.add("Initialized empty context");
        }
    }
    
    /**
     * 비즈니스 규칙 검증
     * 
     * @param request 검증할 요청
     * @param errors 에러 목록
     * @param warnings 경고 목록
     */
    private void validateBusinessRules(
            ApprovalRequest request, 
            List<String> errors, 
            List<String> warnings) {
        
        // 1. 위험 수준에 따른 승인자 수 검증
        validateApproverCount(request, warnings);
        
        // 2. 위험 수준에 따른 타임아웃 검증
        validateTimeout(request, warnings);
        
        // 3. 상태별 필수 필드 검증
        validateStatusSpecificFields(request, errors);
        
        // 4. 역할 검증
        validateRoles(request, warnings);
    }
    
    /**
     * 데이터 일관성 검증
     * 
     * @param request 검증할 요청
     * @param errors 에러 목록
     * @param warnings 경고 목록
     */
    private void validateDataConsistency(
            ApprovalRequest request,
            List<String> errors,
            List<String> warnings) {
        
        ApprovalStatus status = request.getStatus();
        
        // 1. APPROVED 상태 일관성 검증
        if (status == ApprovalStatus.APPROVED) {
            if (request.getApprovedBy() == null || request.getApprovedBy().trim().isEmpty()) {
                errors.add("APPROVED status requires approvedBy field");
            }
            if (request.getApprovedAt() == null) {
                warnings.add("APPROVED status should have approvedAt timestamp");
            }
            if (!request.isApproved()) {
                request.setApproved(true);
                warnings.add("Fixed inconsistency: set approved=true for APPROVED status");
            }
        }
        
        // 2. REJECTED 상태 일관성 검증
        if (status == ApprovalStatus.REJECTED) {
            if (request.getRejectionReason() == null || request.getRejectionReason().trim().isEmpty()) {
                warnings.add("REJECTED status should have rejectionReason");
            }
            if (request.isApproved()) {
                request.setApproved(false);
                warnings.add("Fixed inconsistency: set approved=false for REJECTED status");
            }
        }
        
        // 3. EXPIRED/CANCELLED 상태 일관성 검증
        if (status == ApprovalStatus.EXPIRED || status == ApprovalStatus.CANCELLED) {
            if (request.isApproved()) {
                request.setApproved(false);
                warnings.add("Fixed inconsistency: set approved=false for " + status + " status");
            }
        }
        
        // 4. 시간 일관성 검증
        if (request.getApprovedAt() != null && request.getRequestedAt() != null) {
            if (request.getApprovedAt().isBefore(request.getRequestedAt())) {
                errors.add("approvedAt cannot be before requestedAt");
            }
        }
    }
    
    /**
     * 승인자 수 검증
     * 
     * @param request 검증할 요청
     * @param warnings 경고 목록
     */
    private void validateApproverCount(ApprovalRequest request, List<String> warnings) {
        RiskLevel riskLevel = request.getRiskLevel();
        Integer requiredApprovers = request.getRequiredApprovers();
        
        if (riskLevel == RiskLevel.CRITICAL && requiredApprovers < 2) {
            warnings.add("CRITICAL risk level typically requires at least 2 approvers");
        }
        
        if (riskLevel == RiskLevel.HIGH && requiredApprovers < 1) {
            warnings.add("HIGH risk level requires at least 1 approver");
        }
    }
    
    /**
     * 타임아웃 검증
     * 
     * @param request 검증할 요청
     * @param warnings 경고 목록
     */
    private void validateTimeout(ApprovalRequest request, List<String> warnings) {
        Integer timeout = request.getApprovalTimeout();
        RiskLevel riskLevel = request.getRiskLevel();
        
        if (timeout == null || timeout <= 0) {
            return; // 이미 sanitize에서 처리됨
        }
        
        // 위험 수준에 따른 권장 타임아웃
        if (riskLevel == RiskLevel.CRITICAL && timeout > 120) {
            warnings.add("CRITICAL requests should have shorter timeout (recommended: 120 seconds)");
        }
        
        if (riskLevel == RiskLevel.INFO && timeout < 600) {
            warnings.add("INFO level requests can have longer timeout (recommended: 600 seconds)");
        }
    }
    
    /**
     * 상태별 필수 필드 검증
     * 
     * @param request 검증할 요청
     * @param errors 에러 목록
     */
    private void validateStatusSpecificFields(ApprovalRequest request, List<String> errors) {
        ApprovalStatus status = request.getStatus();
        
        switch (status) {
            case APPROVED:
                if (request.getApprovedBy() == null || request.getApprovedBy().trim().isEmpty()) {
                    errors.add("APPROVED status requires approvedBy");
                }
                break;
                
            case REJECTED:
                if (request.getRejectionReason() == null || request.getRejectionReason().trim().isEmpty()) {
                    // 경고로 변경 (에러는 너무 엄격할 수 있음)
                    log.debug("REJECTED status without rejectionReason");
                }
                break;
                
            case EXPIRED:
            case CANCELLED:
                // 선택적 필드
                break;
                
            case PENDING:
                // PENDING 상태는 추가 필드 불필요
                break;
                
            default:
                log.warn("Unknown status: {}", status);
        }
    }
    
    /**
     * 역할 검증
     * 
     * @param request 검증할 요청
     * @param warnings 경고 목록
     */
    private void validateRoles(ApprovalRequest request, List<String> warnings) {
        Set<String> requiredRoles = request.getRequiredRoles();
        
        if (requiredRoles == null || requiredRoles.isEmpty()) {
            RiskLevel riskLevel = request.getRiskLevel();
            if (riskLevel == RiskLevel.CRITICAL || riskLevel == RiskLevel.HIGH) {
                warnings.add("High risk requests should specify required roles");
            }
        }
    }
    
    /**
     * 검증 결과 클래스
     */
    public static class ValidationResult {
        private final boolean valid;
        private final List<String> errors;
        private final List<String> warnings;
        
        private ValidationResult(boolean valid, List<String> errors, List<String> warnings) {
            this.valid = valid;
            this.errors = errors != null ? errors : Collections.emptyList();
            this.warnings = warnings != null ? warnings : Collections.emptyList();
        }
        
        public static ValidationResult success(List<String> warnings) {
            return new ValidationResult(true, Collections.emptyList(), warnings);
        }
        
        public static ValidationResult failure(String error) {
            return new ValidationResult(false, Collections.singletonList(error), Collections.emptyList());
        }
        
        public static ValidationResult failure(List<String> errors, List<String> warnings) {
            return new ValidationResult(false, errors, warnings);
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public List<String> getErrors() {
            return Collections.unmodifiableList(errors);
        }
        
        public List<String> getWarnings() {
            return Collections.unmodifiableList(warnings);
        }
        
        public boolean hasWarnings() {
            return !warnings.isEmpty();
        }
        
        @Override
        public String toString() {
            return String.format("ValidationResult{valid=%s, errors=%d, warnings=%d}", 
                valid, errors.size(), warnings.size());
        }
    }
}