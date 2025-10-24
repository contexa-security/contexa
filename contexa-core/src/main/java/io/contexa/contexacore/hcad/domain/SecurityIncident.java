package io.contexa.contexacore.hcad.domain;

import io.contexa.contexacore.autonomous.tiered.SecurityDecision;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;

/**
 * 보안 인시던트 기록
 *
 * 사용자별 보안 이벤트 이력 추적
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityIncident implements Serializable {
    private static final long serialVersionUID = 1L;

    private String eventId;
    private String eventType;
    private String sourceIp;
    private RiskLevel riskLevel;
    private SecurityDecision.Action finalAction;
    private double trustScoreBefore;
    private double trustScoreAfter;
    private Instant timestamp;
}
