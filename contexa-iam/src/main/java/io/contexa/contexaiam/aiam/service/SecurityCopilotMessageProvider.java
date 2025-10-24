package io.contexa.contexaiam.aiam.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Security Copilot 메시지 제공자
 * 
 * 하드코딩 제거 - 메시지 외부화
 * 다국어 지원 준비
 * 일관된 메시지 관리
 */
@Component
@Slf4j
public class SecurityCopilotMessageProvider {

    // ==================== 검증 오류 메시지 ====================

    /**
     * Null 요청 메시지
     */
    public String getNullRequestMessage() {
        return "Security Copilot 요청 객체를 확인할 수 없습니다";
    }

    /**
     * 보안 질의 누락 메시지
     */
    public String getMissingSecurityQueryMessage() {
        return "보안 질의 내용이 필요합니다";
    }

    /**
     * 사용자 ID 누락 메시지
     */
    public String getMissingUserIdMessage() {
        return "사용자 ID가 필요합니다";
    }

    /**
     * 사용자 ID 형식 오류 메시지
     */
    public String getInvalidUserIdFormatMessage() {
        return "사용자 ID 형식이 올바르지 않습니다";
    }

    /**
     * 질의 길이 초과 메시지
     */
    public String getQueryTooLongMessage(int maxLength) {
        return String.format("보안 질의 내용이 너무 깁니다 (최대 %d자)", maxLength);
    }

    /**
     * 사용자 ID 길이 초과 메시지
     */
    public String getUserIdTooLongMessage(int maxLength) {
        return String.format("사용자 ID가 너무 깁니다 (최대 %d자)", maxLength);
    }

    // ==================== 처리 상태 메시지 ====================

    /**
     * 분석 시작 메시지
     */
    public String getAnalysisStartMessage(String query) {
        return String.format("보안 분석을 시작합니다: %s", query);
    }

    /**
     * 분석 완료 메시지
     */
    public String getAnalysisCompleteMessage(double securityScore) {
        return String.format("보안 분석이 완료되었습니다 (보안 점수: %.1f점)", securityScore);
    }

    /**
     * 분석 실패 메시지
     */
    public String getAnalysisFailureMessage(String reason) {
        return String.format("보안 분석 중 오류가 발생했습니다: %s", reason);
    }

    // ==================== 스트리밍 메시지 ====================

    /**
     * 스트리밍 시작 메시지
     */
    public String getStreamingStartMessage() {
        return "실시간 보안 분석을 시작합니다...";
    }

    /**
     * 스트리밍 완료 메시지
     */
    public String getStreamingCompleteMessage() {
        return "실시간 보안 분석이 완료되었습니다";
    }

    /**
     * 스트리밍 오류 메시지
     */
    public String getStreamingErrorMessage(String error) {
        return String.format("스트리밍 처리 중 오류: %s", error);
    }

    // ==================== 표준 공정 메시지 ====================

    /**
     * 표준 공정 시작 메시지
     */
    public String getStandardProcessStartMessage() {
        return "표준 공정을 통한 보안 분석을 시작합니다";
    }

    /**
     * 표준 공정 완료 메시지
     */
    public String getStandardProcessCompleteMessage() {
        return "표준 공정을 통한 보안 분석이 완료되었습니다";
    }

    /**
     * 표준 공정 실패 메시지
     */
    public String getStandardProcessFailureMessage(String reason) {
        return String.format("표준 공정 처리 중 오류가 발생했습니다: %s", reason);
    }

    // ==================== 관리자 페이지 메시지 ====================

    /**
     * 관리자 페이지 시작 메시지
     */
    public String getAdminPageStartMessage() {
        return "관리자 페이지를 통한 보안 분석을 시작합니다";
    }

    /**
     * 관리자 페이지 완료 메시지
     */
    public String getAdminPageCompleteMessage() {
        return "관리자 페이지를 통한 보안 분석이 완료되었습니다";
    }

    // ==================== 시스템 메시지 ====================

    /**
     * 시스템 초기화 메시지
     */
    public String getSystemInitMessage() {
        return "Security Copilot 시스템이 초기화되었습니다";
    }

    /**
     * 시스템 준비 완료 메시지
     */
    public String getSystemReadyMessage() {
        return "Security Copilot 시스템이 준비되었습니다";
    }

    /**
     * 시스템 경고 메시지
     */
    public String getSystemWarningMessage(String warning) {
        return String.format("시스템 경고: %s", warning);
    }

    // ==================== 헬퍼 메서드 ====================

    /**
     * 메시지 포맷팅 헬퍼
     */
    public String formatMessage(String template, Object... args) {
        try {
            return String.format(template, args);
        } catch (Exception e) {
            log.warn("메시지 포맷팅 실패: {}", template, e);
            return template; // 원본 템플릿 반환
        }
    }

    /**
     * 에러 메시지 안전 생성
     */
    public String createSafeErrorMessage(String operation, Throwable error) {
        String errorMessage = error != null ? error.getMessage() : "알 수 없는 오류";
        return String.format("%s 처리 중 오류가 발생했습니다: %s", operation, errorMessage);
    }

    /**
     * 진행 상황 메시지
     */
    public String getProgressMessage(String step, int current, int total) {
        return String.format("[%d/%d] %s 진행 중...", current, total, step);
    }

    /**
     * 완료 퍼센트 메시지
     */
    public String getProgressPercentMessage(String operation, double percent) {
        return String.format("%s: %.1f%% 완료", operation, percent);
    }
} 