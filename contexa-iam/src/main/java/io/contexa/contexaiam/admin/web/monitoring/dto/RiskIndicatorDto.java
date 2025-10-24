package io.contexa.contexaiam.admin.web.monitoring.dto;

/**
 * 대시보드에 표시될 위험 지표 정보를 담는 DTO 입니다.
 */
public record RiskIndicatorDto(
        String level, // "CRITICAL", "HIGH", "MEDIUM"
        String title, // "MFA 미사용 관리자 계정 발견"
        String description, // "2명의 관리자 계정에 MFA가 설정되지 않았습니다."
        String link // 관련 관리 페이지로 이동하는 링크
) {}
