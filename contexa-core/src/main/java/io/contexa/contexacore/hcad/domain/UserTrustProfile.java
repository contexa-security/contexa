package io.contexa.contexacore.hcad.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 사용자 신뢰 프로필
 *
 * Zero Trust 아키텍처에서 사용자의 신뢰 수준과 행동 패턴을 추적
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserTrustProfile implements Serializable {
    private static final long serialVersionUID = 1L;

    private String userId;
    private double currentTrustScore;
    private double baselineTrustScore;
    private RiskLevel riskLevel;
    private Instant profileCreatedAt;
    private Instant lastUpdatedAt;
    private long analysisCount;
    private Map<String, Object> behaviorPatterns;
    private List<SecurityIncident> securityIncidents;
    private Map<String, Double> adaptiveThresholds;
}
