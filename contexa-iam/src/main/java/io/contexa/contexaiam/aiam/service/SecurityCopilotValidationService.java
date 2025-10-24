package io.contexa.contexaiam.aiam.service;

import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotItem;
import io.contexa.contexaiam.aiam.protocol.request.SecurityCopilotRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Security Copilot 요청 검증 서비스
 * 
 * 하드코딩 제거 - 검증 로직 외부화
 * 단일 책임 원칙 준수
 * 재사용 가능한 검증 로직
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityCopilotValidationService {

    private final SecurityCopilotMessageProvider messageProvider;

    /**
     * SecurityCopilot 요청 종합 검증
     * 
     * @param request 검증할 요청 객체
     * @return 검증 결과 - null이면 검증 통과, 문자열이면 오류 메시지
     */
    public String validateRequest(SecurityCopilotItem request) {
        log.debug("SecurityCopilot 요청 검증 시작");
        
        // 1. Null 검증
        String nullValidationResult = validateNullRequest(request);
        if (nullValidationResult != null) {
            return nullValidationResult;
        }
        
        // 2. 필수 필드 검증
        String requiredFieldsResult = validateRequiredFields(request);
        if (requiredFieldsResult != null) {
            return requiredFieldsResult;
        }
        
        // 3. 형식 검증
        String formatValidationResult = validateFormat(request);
        if (formatValidationResult != null) {
            return formatValidationResult;
        }
        
        // 4. 비즈니스 규칙 검증
        String businessRulesResult = validateBusinessRules(request);
        if (businessRulesResult != null) {
            return businessRulesResult;
        }
        
        log.debug("SecurityCopilot 요청 검증 완료");
        return null; // 검증 통과
    }

    /**
     * Null 요청 검증
     */
    private String validateNullRequest(SecurityCopilotItem request) {
        if (request == null) {
            return messageProvider.getNullRequestMessage();
        }
        return null;
    }

    /**
     * 필수 필드 검증
     */
    private String validateRequiredFields(SecurityCopilotItem request) {
        // 보안 질의 필수 검증
        if (request.getSecurityQuery() == null || request.getSecurityQuery().trim().isEmpty()) {
            return messageProvider.getMissingSecurityQueryMessage();
        }
        
        // 사용자 ID 필수 검증
        if (request.getUserId() == null || request.getUserId().trim().isEmpty()) {
            return messageProvider.getMissingUserIdMessage();
        }
        
        return null;
    }

    /**
     * 형식 검증
     */
    private String validateFormat(SecurityCopilotItem request) {
        // 사용자 ID 형식 검증
        if (!isValidUserId(request.getUserId())) {
            return messageProvider.getInvalidUserIdFormatMessage();
        }
        
        return null;
    }

    /**
     * 비즈니스 규칙 검증
     */
    private String validateBusinessRules(SecurityCopilotItem request) {
        // 보안 질의 길이 제한
        if (request.getSecurityQuery().length() > getMaxQueryLength()) {
            return messageProvider.getQueryTooLongMessage(getMaxQueryLength());
        }
        
        // 사용자 ID 길이 제한
        if (request.getUserId().length() > getMaxUserIdLength()) {
            return messageProvider.getUserIdTooLongMessage(getMaxUserIdLength());
        }
        
        return null;
    }

    /**
     * 사용자 ID 형식 유효성 검증
     */
    private boolean isValidUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            return false;
        }
        
        // 기본적인 형식 검증 (영문, 숫자, 하이픈, 언더스코어, 점 허용)
        return userId.matches("^[a-zA-Z0-9._-]+$") && userId.length() <= getMaxUserIdLength();
    }

    /**
     * 📏 최대 질의 길이 제한
     */
    private int getMaxQueryLength() {
        return 1000; // 보안상 1000자 제한
    }

    /**
     * 📏 최대 사용자 ID 길이 제한
     */
    private int getMaxUserIdLength() {
        return 100; // 100자 제한
    }

    /**
     * 빠른 검증 - 기본적인 null/empty 검증만
     */
    public boolean isValidBasic(SecurityCopilotRequest request) {
        return request != null 
            && request.getSecurityQuery() != null 
            && !request.getSecurityQuery().trim().isEmpty()
            && request.getUserId() != null 
            && !request.getUserId().trim().isEmpty();
    }

    /**
     * 스트리밍 요청 특화 검증
     */
    public String validateStreamingRequest(SecurityCopilotItem request) {
        // 기본 검증 먼저 수행
        String basicValidation = validateRequest(request);
        if (basicValidation != null) {
            return basicValidation;
        }
        
        // 스트리밍 특화 검증 로직 추가 가능
        // 예: 실시간 처리에 적합한 질의 길이 제한 등
        
        return null; // 검증 통과
    }
} 