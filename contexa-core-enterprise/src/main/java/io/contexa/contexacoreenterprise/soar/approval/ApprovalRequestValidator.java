package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacore.domain.ApprovalRequest.RiskLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class ApprovalRequestValidator {
    
    private static final String DEFAULT_ORGANIZATION_ID = "default-org";
    private static final String DEFAULT_REQUESTED_BY = "system";
    private static final Integer DEFAULT_APPROVAL_TIMEOUT = 300; 

    public ValidationResult validateAndSanitize(ApprovalRequest request) {
        if (request == null) {
            return ValidationResult.failure("ApprovalRequest is null");
        }

        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        validateRequiredFields(request, errors);

        sanitizeFields(request, warnings);

        validateBusinessRules(request, errors, warnings);

        validateDataConsistency(request, errors, warnings);

        if (!errors.isEmpty()) {
            log.error("Validation failed for request {}: {}", 
                request.getRequestId(), errors);
            return ValidationResult.failure(errors, warnings);
        }
        
        if (!warnings.isEmpty()) {
            log.warn("Validation warnings for request {}: {}", 
                request.getRequestId(), warnings);
        }
        
                return ValidationResult.success(warnings);
    }

    private void validateRequiredFields(ApprovalRequest request, List<String> errors) {
        
        if (request.getRequestId() == null || request.getRequestId().trim().isEmpty()) {
            errors.add("requestId is required");
        }

        if (request.getToolName() == null || request.getToolName().trim().isEmpty()) {
            errors.add("toolName is required");
        }

        if (request.getStatus() == null) {
            errors.add("status is required");
        }

        if (request.getRiskLevel() == null) {
            errors.add("riskLevel is required");
        }

        if (request.getRequestedAt() == null) {
            errors.add("requestedAt is required");
        }
    }

    private void sanitizeFields(ApprovalRequest request, List<String> warnings) {
        
        if (request.getRequestId() == null || request.getRequestId().trim().isEmpty()) {
            String newId = UUID.randomUUID().toString();
            request.setRequestId(newId);
            warnings.add("Generated new requestId: " + newId);
        }

        if (request.getStatus() == null) {
            request.setStatus(ApprovalStatus.PENDING);
            warnings.add("Set default status: PENDING");
        }

        if (request.getRiskLevel() == null) {
            request.setRiskLevel(RiskLevel.MEDIUM);
            warnings.add("Set default riskLevel: MEDIUM");
        }

        if (request.getRequestedAt() == null) {
            request.setRequestedAt(LocalDateTime.now());
            warnings.add("Set requestedAt to current time");
        }

        if (request.getRequestedBy() == null || request.getRequestedBy().trim().isEmpty()) {
            request.setRequestedBy(DEFAULT_REQUESTED_BY);
            warnings.add("Set default requestedBy: " + DEFAULT_REQUESTED_BY);
        }

        if (request.getOrganizationId() == null || request.getOrganizationId().trim().isEmpty()) {
            request.setOrganizationId(DEFAULT_ORGANIZATION_ID);
            warnings.add("Set default organizationId: " + DEFAULT_ORGANIZATION_ID);
        }

        if (request.getApprovalTimeout() == null || request.getApprovalTimeout() <= 0) {
            request.setApprovalTimeout(DEFAULT_APPROVAL_TIMEOUT);
            warnings.add("Set default approvalTimeout: " + DEFAULT_APPROVAL_TIMEOUT + " seconds");
        }

        if (request.getRequiredApprovers() == null || request.getRequiredApprovers() < 1) {
            request.setRequiredApprovers(1);
            warnings.add("Set default requiredApprovers: 1");
        }

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

    private void validateBusinessRules(
            ApprovalRequest request, 
            List<String> errors, 
            List<String> warnings) {

        validateApproverCount(request, warnings);

        validateTimeout(request, warnings);

        validateStatusSpecificFields(request, errors);

        validateRoles(request, warnings);
    }

    private void validateDataConsistency(
            ApprovalRequest request,
            List<String> errors,
            List<String> warnings) {
        
        ApprovalStatus status = request.getStatus();

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

        if (status == ApprovalStatus.REJECTED) {
            if (request.getRejectionReason() == null || request.getRejectionReason().trim().isEmpty()) {
                warnings.add("REJECTED status should have rejectionReason");
            }
            if (request.isApproved()) {
                request.setApproved(false);
                warnings.add("Fixed inconsistency: set approved=false for REJECTED status");
            }
        }

        if (status == ApprovalStatus.EXPIRED || status == ApprovalStatus.CANCELLED) {
            if (request.isApproved()) {
                request.setApproved(false);
                warnings.add("Fixed inconsistency: set approved=false for " + status + " status");
            }
        }

        if (request.getApprovedAt() != null && request.getRequestedAt() != null) {
            if (request.getApprovedAt().isBefore(request.getRequestedAt())) {
                errors.add("approvedAt cannot be before requestedAt");
            }
        }
    }

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

    private void validateTimeout(ApprovalRequest request, List<String> warnings) {
        Integer timeout = request.getApprovalTimeout();
        RiskLevel riskLevel = request.getRiskLevel();
        
        if (timeout == null || timeout <= 0) {
            return; 
        }

        if (riskLevel == RiskLevel.CRITICAL && timeout > 120) {
            warnings.add("CRITICAL requests should have shorter timeout (recommended: 120 seconds)");
        }
        
        if (riskLevel == RiskLevel.INFO && timeout < 600) {
            warnings.add("INFO level requests can have longer timeout (recommended: 600 seconds)");
        }
    }

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
                    
                                    }
                break;
                
            case EXPIRED:
            case CANCELLED:
                
                break;
                
            case PENDING:
                
                break;
                
            default:
                log.warn("Unknown status: {}", status);
        }
    }

    private void validateRoles(ApprovalRequest request, List<String> warnings) {
        Set<String> requiredRoles = request.getRequiredRoles();
        
        if (requiredRoles == null || requiredRoles.isEmpty()) {
            RiskLevel riskLevel = request.getRiskLevel();
            if (riskLevel == RiskLevel.CRITICAL || riskLevel == RiskLevel.HIGH) {
                warnings.add("High risk requests should specify required roles");
            }
        }
    }

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