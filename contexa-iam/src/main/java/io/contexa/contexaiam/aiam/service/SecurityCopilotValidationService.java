package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotItem;
import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@RequiredArgsConstructor
@Slf4j
public class SecurityCopilotValidationService {

    private final SecurityCopilotMessageProvider messageProvider;

    
    public String validateRequest(SecurityCopilotItem request) {
        log.debug("SecurityCopilot 요청 검증 시작");
        
        
        String nullValidationResult = validateNullRequest(request);
        if (nullValidationResult != null) {
            return nullValidationResult;
        }
        
        
        String requiredFieldsResult = validateRequiredFields(request);
        if (requiredFieldsResult != null) {
            return requiredFieldsResult;
        }
        
        
        String formatValidationResult = validateFormat(request);
        if (formatValidationResult != null) {
            return formatValidationResult;
        }
        
        
        String businessRulesResult = validateBusinessRules(request);
        if (businessRulesResult != null) {
            return businessRulesResult;
        }
        
        log.debug("SecurityCopilot 요청 검증 완료");
        return null; 
    }

    
    private String validateNullRequest(SecurityCopilotItem request) {
        if (request == null) {
            return messageProvider.getNullRequestMessage();
        }
        return null;
    }

    
    private String validateRequiredFields(SecurityCopilotItem request) {
        
        if (request.getSecurityQuery() == null || request.getSecurityQuery().trim().isEmpty()) {
            return messageProvider.getMissingSecurityQueryMessage();
        }
        
        
        if (request.getUserId() == null || request.getUserId().trim().isEmpty()) {
            return messageProvider.getMissingUserIdMessage();
        }
        
        return null;
    }

    
    private String validateFormat(SecurityCopilotItem request) {
        
        if (!isValidUserId(request.getUserId())) {
            return messageProvider.getInvalidUserIdFormatMessage();
        }
        
        return null;
    }

    
    private String validateBusinessRules(SecurityCopilotItem request) {
        
        if (request.getSecurityQuery().length() > getMaxQueryLength()) {
            return messageProvider.getQueryTooLongMessage(getMaxQueryLength());
        }
        
        
        if (request.getUserId().length() > getMaxUserIdLength()) {
            return messageProvider.getUserIdTooLongMessage(getMaxUserIdLength());
        }
        
        return null;
    }

    
    private boolean isValidUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            return false;
        }
        
        
        return userId.matches("^[a-zA-Z0-9._-]+$") && userId.length() <= getMaxUserIdLength();
    }

    
    private int getMaxQueryLength() {
        return 1000; 
    }

    
    private int getMaxUserIdLength() {
        return 100; 
    }

    
    public boolean isValidBasic(SecurityCopilotRequest request) {
        return request != null 
            && request.getSecurityQuery() != null 
            && !request.getSecurityQuery().trim().isEmpty()
            && request.getUserId() != null 
            && !request.getUserId().trim().isEmpty();
    }

    
    public String validateStreamingRequest(SecurityCopilotItem request) {
        
        String basicValidation = validateRequest(request);
        if (basicValidation != null) {
            return basicValidation;
        }
        
        
        
        
        return null; 
    }
} 