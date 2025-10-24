package io.contexa.contexaiam.admin.web.monitoring.dto;

import java.util.List;

/**
 * 대시보드에 표시될 조직의 정량적인 보안 점수를 담는 DTO 입니다.
 */
public record SecurityScoreDto(
        int score, // 0-100 사이의 점수
        String summary, // "MFA 활성화율이 점수에 큰 영향을 미칩니다." 와 같은 요약
        List<ScoreFactor> factors // 점수 구성 요소
) {
    /**
     * 점수를 구성하는 개별 요인
     * @param name 요인 이름 (예: "관리자 MFA 활성화율")
     * @param value 현재 값 (예: 80 (%))
     * @param weight 점수 가중치 (0.0 ~ 1.0)
     */
    public record ScoreFactor(String name, int value, double weight, String description) {}
}