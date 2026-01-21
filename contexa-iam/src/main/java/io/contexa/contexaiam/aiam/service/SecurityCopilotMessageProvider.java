package io.contexa.contexaiam.aiam.service;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SecurityCopilotMessageProvider {

    public String getNullRequestMessage() {
        return "Security Copilot 요청 객체를 확인할 수 없습니다";
    }

    public String getMissingSecurityQueryMessage() {
        return "보안 질의 내용이 필요합니다";
    }

    public String getMissingUserIdMessage() {
        return "사용자 ID가 필요합니다";
    }

    public String getInvalidUserIdFormatMessage() {
        return "사용자 ID 형식이 올바르지 않습니다";
    }

    public String getQueryTooLongMessage(int maxLength) {
        return String.format("보안 질의 내용이 너무 깁니다 (최대 %d자)", maxLength);
    }

    public String getUserIdTooLongMessage(int maxLength) {
        return String.format("사용자 ID가 너무 깁니다 (최대 %d자)", maxLength);
    }

    public String getAnalysisStartMessage(String query) {
        return String.format("보안 분석을 시작합니다: %s", query);
    }

    public String getAnalysisCompleteMessage(double securityScore) {
        return String.format("보안 분석이 완료되었습니다 (보안 점수: %.1f점)", securityScore);
    }

    public String getAnalysisFailureMessage(String reason) {
        return String.format("보안 분석 중 오류가 발생했습니다: %s", reason);
    }

    public String getStreamingStartMessage() {
        return "실시간 보안 분석을 시작합니다...";
    }

    public String getStreamingCompleteMessage() {
        return "실시간 보안 분석이 완료되었습니다";
    }

    public String getStreamingErrorMessage(String error) {
        return String.format("스트리밍 처리 중 오류: %s", error);
    }

    public String getStandardProcessStartMessage() {
        return "표준 공정을 통한 보안 분석을 시작합니다";
    }

    public String getStandardProcessCompleteMessage() {
        return "표준 공정을 통한 보안 분석이 완료되었습니다";
    }

    public String getStandardProcessFailureMessage(String reason) {
        return String.format("표준 공정 처리 중 오류가 발생했습니다: %s", reason);
    }

    public String getAdminPageStartMessage() {
        return "관리자 페이지를 통한 보안 분석을 시작합니다";
    }

    public String getAdminPageCompleteMessage() {
        return "관리자 페이지를 통한 보안 분석이 완료되었습니다";
    }

    public String getSystemInitMessage() {
        return "Security Copilot 시스템이 초기화되었습니다";
    }

    public String getSystemReadyMessage() {
        return "Security Copilot 시스템이 준비되었습니다";
    }

    public String getSystemWarningMessage(String warning) {
        return String.format("시스템 경고: %s", warning);
    }

    public String formatMessage(String template, Object... args) {
        try {
            return String.format(template, args);
        } catch (Exception e) {
            log.warn("메시지 포맷팅 실패: {}", template, e);
            return template; 
        }
    }

    public String createSafeErrorMessage(String operation, Throwable error) {
        String errorMessage = error != null ? error.getMessage() : "알 수 없는 오류";
        return String.format("%s 처리 중 오류가 발생했습니다: %s", operation, errorMessage);
    }

    public String getProgressMessage(String step, int current, int total) {
        return String.format("[%d/%d] %s 진행 중...", current, total, step);
    }

    public String getProgressPercentMessage(String operation, double percent) {
        return String.format("%s: %.1f%% 완료", operation, percent);
    }
} 