package io.contexa.contexacore.hcad.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * 위협 상관관계 분석 결과
 *
 * 시간/IP/행동 패턴 기반 위협 상관관계 정보
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatCorrelationResult {
    private List<String> correlatedEvents;
    private List<String> suspiciousPatterns;
    private double correlationScore;
    private int recentIncidentCount;
    private double behaviorSimilarity;
}
